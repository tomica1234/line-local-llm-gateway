from __future__ import annotations

from typing import Protocol

import httpx


class EmbeddingProvider(Protocol):
    model_id: str

    def embed(self, text: str) -> list[float]: ...


class LocalEmbeddingClient:
    """Small OpenAI-compatible local embedding client with no remote fallback."""

    def __init__(self, *, base_url: str, model_id: str, timeout_seconds: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.timeout_seconds = timeout_seconds

    def embed(self, text: str) -> list[float]:
        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(
                f"{self.base_url}/embeddings",
                json={"model": self.model_id, "input": text[:20_000]},
            )
            response.raise_for_status()
            payload = response.json()
        vector = payload["data"][0]["embedding"]
        if not isinstance(vector, list) or not vector or len(vector) > 65_536:
            raise ValueError("Embedding response has invalid dimensions")
        values = [float(item) for item in vector]
        if any(value != value or abs(value) == float("inf") for value in values):
            raise ValueError("Embedding response contains non-finite values")
        return values
