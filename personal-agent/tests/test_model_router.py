from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from personal_agent.app import create_app
from personal_agent.config import Settings
from personal_agent.core.planner import LLMCapabilityPlanner
from personal_agent.models.qwen import ModelTurn
from personal_agent.models.registry import (
    LocalModelRouter,
    ModelRegistry,
    ModelRequestPurpose,
    ModelSpec,
    ModelTier,
    classify_request_purpose,
)


class RecordingClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[Sequence[dict[str, object]]] = []

    async def complete(self, messages: Sequence[dict[str, object]]) -> str:
        self.calls.append(messages)
        return self.name

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, object]],
        _tools: Sequence[dict[str, object]],
    ) -> ModelTurn:
        self.calls.append(messages)
        return ModelTurn(content=self.name)

    async def complete_vision(
        self, *, image_bytes: bytes, media_type: str, prompt: str
    ) -> ModelTurn:
        assert image_bytes and media_type.startswith("image/") and prompt
        return ModelTurn(content=self.name)


def _spec(tier: ModelTier, *, vision: bool = False) -> ModelSpec:
    return ModelSpec(
        model_id=f"{tier.value}-model",
        provider="local",
        runtime="test",
        endpoint="http://127.0.0.1:8000/v1",
        capabilities=frozenset({tier.value}),
        context_length=32_768,
        cost_class="local",
        latency_class=tier.value,
        supports_tools=tier is ModelTier.STRONG,
        supports_vision=vision,
        supports_json=True,
    )


def _router(*, vision: bool = True, fast_fallback: bool = False) -> LocalModelRouter:
    registry = ModelRegistry()
    for tier in ModelTier:
        registry.register(tier, _spec(tier, vision=vision and tier is ModelTier.VISION))
    strong = RecordingClient("strong")
    fast = strong if fast_fallback else RecordingClient("fast")
    return LocalModelRouter(
        registry=registry,
        clients={
            ModelTier.FAST: fast,
            ModelTier.STRONG: strong,
            ModelTier.VISION: RecordingClient("vision"),
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "purpose"),
    [
        ("このメール送って", ModelRequestPurpose.TOOL_REASONING),
        ("このrepo直して", ModelRequestPurpose.CODING),
        ("capabilityを計画", ModelRequestPurpose.PLANNING),
        ("複数段階で安全に処理", ModelRequestPurpose.GENERAL),
    ],
)
async def test_short_operational_requests_route_to_strong(
    text: str, purpose: ModelRequestPurpose
) -> None:
    router = _router()

    result = await router.complete_for([{"role": "user", "content": text}], purpose=purpose)

    assert result == "strong"
    selection = router.select(purpose)
    assert selection.tier is ModelTier.STRONG
    assert "permissions" not in selection.model_dump()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "purpose"),
    [
        ("この文章を3語で要約", ModelRequestPurpose.FAST_TEXT),
        ('{"name":"A"}からnameを抽出', ModelRequestPurpose.EXTRACTION),
    ],
)
async def test_explicit_low_risk_text_purposes_route_to_fast(
    text: str, purpose: ModelRequestPurpose
) -> None:
    router = _router()

    assert await router.complete_for([{"role": "user", "content": text}], purpose=purpose) == "fast"
    assert router.select(purpose).tier is ModelTier.FAST


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("このメール送って", ModelRequestPurpose.TOOL_REASONING),
        ("このrepo直して", ModelRequestPurpose.CODING),
        ("capability planningをして", ModelRequestPurpose.PLANNING),
        ("この文章を3語で要約", ModelRequestPurpose.FAST_TEXT),
        ("このJSONからnameを抽出", ModelRequestPurpose.EXTRACTION),
    ],
)
def test_trusted_text_is_classified_by_purpose_not_length(
    text: str, expected: ModelRequestPurpose
) -> None:
    router = _router()

    assert classify_request_purpose(text) is expected
    assert router.select_for_text(text).purpose is expected
    assert router.select_for_text(text).tier is (
        ModelTier.FAST
        if expected in {ModelRequestPurpose.FAST_TEXT, ModelRequestPurpose.EXTRACTION}
        else ModelTier.STRONG
    )
    assert (
        classify_request_purpose("3語で要約", has_tools=True) is ModelRequestPurpose.TOOL_REASONING
    )


def test_agent_deep_path_passes_typed_fast_purpose_for_simple_summary(tmp_path: Path) -> None:
    class PurposeModel:
        def __init__(self) -> None:
            self.purposes: list[ModelRequestPurpose] = []

        async def complete_for(
            self,
            _messages: Sequence[dict[str, object]],
            *,
            purpose: ModelRequestPurpose,
        ) -> str:
            self.purposes.append(purpose)
            return "三語の要約"

        async def complete(self, _messages: Sequence[dict[str, object]]) -> str:
            raise AssertionError("Purpose-aware model must receive complete_for")

    model = PurposeModel()
    app = create_app(Settings(db_path=tmp_path / "router.sqlite3"), model)  # type: ignore[arg-type]

    with TestClient(app) as client:
        response = client.post(
            "/api/messages",
            json={
                "text": "この文章を3語で要約: 安全なローカルエージェントです",
                "source": "web",
                "conversation_id": "router-purpose",
            },
        )

    assert response.status_code == 200
    assert model.purposes == [ModelRequestPurpose.FAST_TEXT]


@pytest.mark.asyncio
async def test_fast_falls_back_to_strong_and_vision_fails_closed_when_unconfigured() -> None:
    fallback = _router(fast_fallback=True)
    selection = fallback.select(ModelRequestPurpose.EXTRACTION)
    assert selection.tier is ModelTier.STRONG
    assert selection.fallback is True

    unavailable = _router(vision=False)
    with pytest.raises(RuntimeError, match="Vision model is not configured"):
        unavailable.select(ModelRequestPurpose.VISION)
    with pytest.raises(RuntimeError, match="Vision model is not configured"):
        await unavailable.complete_vision(
            image_bytes=b"image", media_type="image/png", prompt="describe"
        )

    configured = _router(vision=True)
    assert configured.select(ModelRequestPurpose.VISION).tier is ModelTier.VISION
    assert (
        await configured.complete_vision(
            image_bytes=b"image", media_type="image/png", prompt="describe"
        )
    ).content == "vision"


@pytest.mark.asyncio
async def test_capability_planner_explicitly_requests_strong_planning() -> None:
    class PlannerModel:
        def __init__(self) -> None:
            self.purposes: list[ModelRequestPurpose] = []

        async def complete_for(
            self,
            _messages: Sequence[dict[str, object]],
            *,
            purpose: ModelRequestPurpose,
        ) -> str:
            self.purposes.append(purpose)
            return (
                '{"steps":[{"purpose":"送信内容を確定",'
                '"requested_capabilities":["messages.write"]}]}'
            )

        async def complete(self, _messages: Sequence[dict[str, object]]) -> str:
            raise AssertionError("Capability planning must use the explicit planning purpose")

    model = PlannerModel()
    plan, evidence = await LLMCapabilityPlanner(model).plan("このメール送って")  # type: ignore[arg-type]

    assert model.purposes == [ModelRequestPurpose.PLANNING]
    assert evidence["source"] == "llm_proposal_validated"
    assert plan[0].permissions == frozenset({"messages.write"})
