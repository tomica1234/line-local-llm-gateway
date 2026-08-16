import json

import httpx
import pytest

from personal_agent.config import Settings
from personal_agent.models.qwen import QwenClient


@pytest.mark.asyncio
async def test_qwen_client_disables_thinking_and_parses_tool_calls() -> None:
    requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "calendar.list",
                                        "arguments": '{"date":"2026-08-14"}',
                                    },
                                }
                            ],
                        }
                    }
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
            },
        )

    client = QwenClient(
        Settings(model_api_key="model-secret"),
        transport=httpx.MockTransport(handler),
    )
    turn = await client.complete_with_tools(
        [{"role": "user", "content": "今日の予定を確認して"}],
        [
            {
                "name": "calendar.list",
                "description": "予定を取得する",
                "parameters": {
                    "type": "object",
                    "properties": {"date": {"type": "string"}},
                    "required": ["date"],
                },
            }
        ],
    )

    assert requests[0]["chat_template_kwargs"] == {"enable_thinking": False}
    assert requests[0]["tool_choice"] == "auto"
    assert turn.tool_calls[0].name == "calendar.list"
    assert turn.tool_calls[0].arguments == {"date": "2026-08-14"}
    assert turn.metrics["total_tokens"] == 20


@pytest.mark.asyncio
async def test_qwen_client_can_enable_thinking_explicitly() -> None:
    request_payload: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        request_payload.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": "回答"}}]},
        )

    client = QwenClient(
        Settings(model_enable_thinking=True),
        transport=httpx.MockTransport(handler),
    )
    assert await client.complete([{"role": "user", "content": "質問"}]) == "回答"
    assert request_payload["chat_template_kwargs"] == {"enable_thinking": True}
