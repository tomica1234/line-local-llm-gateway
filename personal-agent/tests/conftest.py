from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from personal_agent.app import create_app
from personal_agent.config import Settings


class FakeModel:
    def __init__(self, response: str = "ローカルモデルからの応答です。") -> None:
        self.response = response
        self.calls: list[Sequence[dict[str, str]]] = []
        self.error: Exception | None = None

    async def complete(self, messages: Sequence[dict[str, str]]) -> str:
        self.calls.append(messages)
        if self.error:
            raise self.error
        return self.response


@pytest.fixture
def fake_model() -> FakeModel:
    return FakeModel()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "agent.sqlite3",
        model_base_url="http://127.0.0.1:8000/v1",
        admin_token="test-admin-token",
        activity_token="test-activity-token",
    )


@pytest.fixture
def app(settings: Settings, fake_model: FakeModel):
    return create_app(settings, fake_model)


@pytest.fixture
def client(app) -> TestClient:
    with TestClient(app) as test_client:
        yield test_client
