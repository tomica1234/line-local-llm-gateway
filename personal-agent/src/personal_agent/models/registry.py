from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict

from ..config import Settings
from .qwen import ModelClient, ModelTurn, QwenClient


class ModelTier(StrEnum):
    FAST = "fast"
    STRONG = "strong"
    VISION = "vision"


class ModelSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_id: str
    provider: str
    runtime: str
    endpoint: str
    capabilities: frozenset[str]
    context_length: int
    cost_class: str
    latency_class: str
    supports_tools: bool
    supports_vision: bool
    supports_json: bool


class ModelRegistry:
    def __init__(self) -> None:
        self._models: dict[ModelTier, ModelSpec] = {}

    def register(self, tier: ModelTier, specification: ModelSpec) -> None:
        self._models[tier] = specification

    def get(self, tier: ModelTier) -> ModelSpec:
        return self._models[tier]

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            tier.value: specification.model_dump(mode="json")
            for tier, specification in self._models.items()
        }


class LocalModelRouter:
    """Routes only among operator-configured local models; it grants no capabilities."""

    def __init__(
        self,
        *,
        registry: ModelRegistry,
        clients: dict[ModelTier, ModelClient],
    ) -> None:
        self.registry = registry
        self.clients = clients
        self.model = registry.get(ModelTier.STRONG).model_id

    @classmethod
    def from_settings(cls, settings: Settings) -> LocalModelRouter:
        registry = ModelRegistry()
        strong = QwenClient(settings)
        fast_endpoint = settings.fast_model_base_url or settings.model_base_url
        fast_name = settings.fast_model_name or settings.model_name
        fast = (
            strong
            if (fast_endpoint, fast_name) == (settings.model_base_url, settings.model_name)
            else QwenClient(settings, base_url=fast_endpoint, model_name=fast_name)
        )
        vision_endpoint = settings.vision_model_base_url or settings.model_base_url
        vision_name = settings.vision_model_name or settings.model_name
        vision = (
            strong
            if (vision_endpoint, vision_name) == (settings.model_base_url, settings.model_name)
            else QwenClient(settings, base_url=vision_endpoint, model_name=vision_name)
        )
        registry.register(
            ModelTier.FAST,
            ModelSpec(
                model_id=fast_name,
                provider="local-openai-compatible",
                runtime="llama.cpp",
                endpoint=fast_endpoint,
                capabilities=frozenset({"intent", "extraction", "short_answer", "json"}),
                context_length=32_768,
                cost_class="local",
                latency_class="fast",
                supports_tools=False,
                supports_vision=False,
                supports_json=True,
            ),
        )
        registry.register(
            ModelTier.STRONG,
            ModelSpec(
                model_id=settings.model_name,
                provider="local-openai-compatible",
                runtime="llama.cpp",
                endpoint=settings.model_base_url,
                capabilities=frozenset({"planning", "reasoning", "tools", "json"}),
                context_length=131_072,
                cost_class="local",
                latency_class="strong",
                supports_tools=True,
                supports_vision=False,
                supports_json=True,
            ),
        )
        registry.register(
            ModelTier.VISION,
            ModelSpec(
                model_id=vision_name,
                provider="local-openai-compatible",
                runtime="llama.cpp",
                endpoint=vision_endpoint,
                capabilities=frozenset({"vision", "ocr", "screenshot_grounding"}),
                context_length=32_768,
                cost_class="local",
                latency_class="vision",
                supports_tools=False,
                supports_vision=bool(settings.vision_model_name),
                supports_json=True,
            ),
        )
        return cls(
            registry=registry,
            clients={ModelTier.FAST: fast, ModelTier.STRONG: strong, ModelTier.VISION: vision},
        )

    async def complete(self, messages: Sequence[dict[str, object]]) -> str:
        characters = sum(len(str(message.get("content", ""))) for message in messages)
        tier = ModelTier.FAST if characters <= 2_000 else ModelTier.STRONG
        return await self.clients[tier].complete(messages)

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> ModelTurn:
        return await self.clients[ModelTier.STRONG].complete_with_tools(messages, tools)

    async def complete_vision(
        self, *, image_bytes: bytes, media_type: str, prompt: str
    ) -> ModelTurn:
        specification = self.registry.get(ModelTier.VISION)
        if not specification.supports_vision:
            raise RuntimeError("Vision model is not configured")
        client = self.clients[ModelTier.VISION]
        complete_vision = getattr(client, "complete_vision", None)
        if complete_vision is None:
            raise RuntimeError("Configured vision client does not support image input")
        return await complete_vision(
            image_bytes=image_bytes,
            media_type=media_type,
            prompt=prompt,
        )
