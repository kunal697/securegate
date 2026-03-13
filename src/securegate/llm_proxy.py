"""LLM proxy adapter - model-agnostic interface."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import AsyncIterator, Optional

logger = logging.getLogger(__name__)

# Retry on rate limit (429) or temporary error (503)
GEMINI_RETRY_STATUSES = (429, 503)
GEMINI_RETRY_ATTEMPTS = 3
GEMINI_RETRY_BACKOFF = (1.0, 2.0, 4.0)

from pydantic import BaseModel


class ChatMessage(BaseModel):
    """Chat message."""

    role: str  # system, user, assistant
    content: str


class LLMResponse(BaseModel):
    """LLM response."""

    content: str
    model: str = ""
    usage: Optional[dict] = None


class LLMProxy(ABC):
    """Abstract LLM proxy adapter."""

    @abstractmethod
    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
    ) -> LLMResponse:
        """Send chat completion request."""
        ...

    @abstractmethod
    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
    ) -> AsyncIterator[str]:
        """Stream chat completion chunks."""
        ...


class OpenAIDirectProxy(LLMProxy):
    """Direct OpenAI API proxy. Requires OPENAI_API_KEY."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None) -> None:
        self._api_key = api_key
        self._base_url = base_url

    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
    ) -> LLMResponse:
        from openai import AsyncOpenAI
        import os

        client = AsyncOpenAI(
            api_key=self._api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=self._base_url,
        )
        resp = await client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[{"role": m.role, "content": m.content} for m in messages],
        )
        choice = resp.choices[0] if resp.choices else None
        content = choice.message.content if choice else ""
        return LLMResponse(
            content=content,
            model=resp.model or "",
            usage={"prompt_tokens": resp.usage.prompt_tokens, "completion_tokens": resp.usage.completion_tokens} if resp.usage else None,
        )

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
    ) -> AsyncIterator[str]:
        from openai import AsyncOpenAI
        import os

        client = AsyncOpenAI(
            api_key=self._api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=self._base_url,
        )
        stream = await client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[{"role": m.role, "content": m.content} for m in messages],
            stream=True,
        )
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content


class GeminiProxy(LLMProxy):
    """Chat proxy using Google Gemini API. Requires GEMINI_API_KEY."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.0-flash") -> None:
        self._api_key = (api_key or "").strip()
        self._model = (model or "gemini-2.0-flash").strip()

    async def chat(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
    ) -> LLMResponse:
        import httpx

        model_name = model or self._model
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        # Map chat messages to Gemini contents (user/model)
        contents = []
        for m in messages:
            role = "user" if m.role in ("user", "system") else "model"
            contents.append({"role": role, "parts": [{"text": m.content or ""}]})
        payload = {"contents": contents, "generationConfig": {"maxOutputTokens": 2048, "temperature": 0.7}}
        headers = {"x-goog-api-key": self._api_key, "Content-Type": "application/json"}

        # Share global 1/sec rate limit with classifier (llm_client.acquire_gemini_rate_limit)
        from securegate.llm_client import acquire_gemini_rate_limit
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, acquire_gemini_rate_limit)

        data = None
        for attempt in range(GEMINI_RETRY_ATTEMPTS):
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                if r.status_code in GEMINI_RETRY_STATUSES and attempt < GEMINI_RETRY_ATTEMPTS - 1:
                    delay = GEMINI_RETRY_BACKOFF[attempt] if attempt < len(GEMINI_RETRY_BACKOFF) else 4.0
                    logger.info(
                        "Gemini rate limited (HTTP %s), retry in %.1fs (attempt %d/%d)",
                        r.status_code, delay, attempt + 1, GEMINI_RETRY_ATTEMPTS,
                    )
                    await asyncio.sleep(delay)
                    continue
                r.raise_for_status()
                data = r.json()
                break
        if data is None:
            raise httpx.HTTPStatusError("Gemini failed after retries", request=r.request, response=r)

        try:
            part = (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [{}])[0]
            content = part.get("text", "").strip()
        except (IndexError, KeyError, TypeError):
            content = ""
        return LLMResponse(content=content, model=model_name, usage=None)

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        model: Optional[str] = None,
    ) -> AsyncIterator[str]:
        # Gemini streaming would use generateContent with stream; for simplicity we fall back to non-stream
        resp = await self.chat(messages, model=model)
        if resp.content:
            yield resp.content
