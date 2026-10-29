"""Minimal Ollama REST client (``/api/chat``, ``/api/embed``, ``/api/version``, ``/api/tags``).

It uses httpx directly with explicit timeouts and response-size limits, so the exact
request we send is visible. It has no tool-calling support by design. Transport-level
failures are raised as ``AIUnavailableError``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from threatlens.errors import AIUnavailableError

log = logging.getLogger(__name__)
MAX_RESPONSE_BYTES = 512 * 1024


@dataclass(frozen=True)
class ChatResult:
    content: str
    model: str
    prompt_tokens: int | None
    output_tokens: int | None
    total_duration_ms: int | None


class OllamaClient:
    def __init__(
        self, host: str, *, timeout: float, transport: httpx.BaseTransport | None = None
    ) -> None:
        self.host = host.rstrip("/")
        self._client = httpx.Client(
            base_url=self.host,
            timeout=httpx.Timeout(timeout, connect=5.0),
            transport=transport,
            follow_redirects=False,
        )

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = self._client.post(path, json=payload)
        except httpx.TimeoutException as exc:
            raise AIUnavailableError("The local AI model timed out.", detail=str(exc)) from exc
        except httpx.HTTPError as exc:
            raise AIUnavailableError(detail=f"{type(exc).__name__}: {exc}") from exc
        if resp.status_code == 404:
            raise AIUnavailableError(
                "The configured AI model is not installed in Ollama.", detail=resp.text[:300]
            )
        if resp.status_code >= 400:
            raise AIUnavailableError(detail=f"HTTP {resp.status_code}: {resp.text[:300]}")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise AIUnavailableError("The AI response was too large.", detail="oversized")
        try:
            data = resp.json()
        except ValueError as exc:
            raise AIUnavailableError(detail="non-JSON response envelope") from exc
        if not isinstance(data, dict):
            raise AIUnavailableError(detail="unexpected response envelope")
        return data

    def version(self) -> str:
        try:
            resp = self._client.get("/api/version", timeout=3.0)
            resp.raise_for_status()
            return str(resp.json().get("version", "unknown"))
        except (httpx.HTTPError, ValueError) as exc:
            raise AIUnavailableError(detail=str(exc)) from exc

    def list_models(self) -> list[str]:
        try:
            resp = self._client.get("/api/tags", timeout=5.0)
            resp.raise_for_status()
            return sorted(m.get("name", "") for m in resp.json().get("models", []))
        except (httpx.HTTPError, ValueError) as exc:
            raise AIUnavailableError(detail=str(exc)) from exc

    def chat_json(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: dict[str, Any],
        num_ctx: int,
        num_predict: int,
    ) -> ChatResult:
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": schema,
            "think": False,
            "options": {"temperature": 0, "num_ctx": num_ctx, "num_predict": num_predict},
        }
        data = self._post("/api/chat", payload)
        message = data.get("message") or {}
        content = message.get("content")
        if not isinstance(content, str):
            raise AIUnavailableError(detail="response missing message.content")
        duration = data.get("total_duration")
        return ChatResult(
            content=content,
            model=str(data.get("model", model)),
            prompt_tokens=data.get("prompt_eval_count"),
            output_tokens=data.get("eval_count"),
            total_duration_ms=int(duration / 1e6) if isinstance(duration, int | float) else None,
        )

    def embed(self, *, model: str, texts: list[str]) -> list[list[float]]:
        data = self._post("/api/embed", {"model": model, "input": texts})
        vectors = data.get("embeddings")
        if (
            not isinstance(vectors, list)
            or len(vectors) != len(texts)
            or not all(isinstance(v, list) and v for v in vectors)
        ):
            raise AIUnavailableError(detail="malformed embeddings response")
        dims = {len(v) for v in vectors}
        if len(dims) != 1:
            raise AIUnavailableError(detail="inconsistent embedding dimensions")
        return vectors
