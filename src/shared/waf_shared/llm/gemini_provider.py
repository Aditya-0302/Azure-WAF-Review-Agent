"""Gemini LLM provider — implements LLMProvider using Google's Gemini API.

Authentication: API key via GEMINI_API_KEY environment variable.

Uses the google-genai SDK (google-genai on PyPI) with its native async interface.
JSON output is requested via response_mime_type="application/json" so callers
can reliably parse structured findings from the response content.
"""

from __future__ import annotations

from waf_shared.domain.errors.infrastructure_errors import (
    LLMQuotaExhaustedError,
    LLMRateLimitError,
)
from waf_shared.llm.provider import LLMResponse


class GeminiProvider:
    """Implements :class:`LLMProvider` against Google Gemini API.

    The ``model_name`` must be a pinned model identifier, e.g. ``"gemini-2.5-pro"``.
    The provider requests JSON output mode on every call so the LLM pipeline can
    parse the response without post-processing markdown fences.
    """

    def __init__(
        self,
        *,
        api_key: str,
        model_name: str = "gemini-2.5-pro",
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required for GeminiProvider")

        from google import genai  # type: ignore[import-untyped]

        self._model_name = model_name
        self._client = genai.Client(api_key=api_key)

    def model_id(self) -> str:
        return self._model_name

    async def chat_complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> LLMResponse:
        from google.genai import types  # type: ignore[import-untyped]

        try:
            response = await self._client.aio.models.generate_content(
                model=self._model_name,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=max_tokens,
                    temperature=temperature,
                    response_mime_type="application/json",
                ),
            )
        except Exception as exc:
            _handle_gemini_error(exc, self._model_name)
            raise  # unreachable; _handle_gemini_error always raises or returns

        content = _extract_text(response)
        usage = getattr(response, "usage_metadata", None)
        prompt_tokens = int(getattr(usage, "prompt_token_count", 0) or 0)
        completion_tokens = int(getattr(usage, "candidates_token_count", 0) or 0)

        return LLMResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            model=self._model_name,
        )

    def count_tokens(self, text: str) -> int:
        # Gemini tokens are roughly comparable to GPT-4 for English; 4-chars/token.
        return max(1, len(text) // 4)

    async def healthcheck(self) -> None:
        """Verify API connectivity with a minimal generation call.

        Raises an exception if the provider is unreachable or misconfigured.
        """
        from google.genai import types  # type: ignore[import-untyped]

        try:
            response = await self._client.aio.models.generate_content(
                model=self._model_name,
                contents="ping",
                config=types.GenerateContentConfig(max_output_tokens=1),
            )
            _ = _extract_text(response)
        except Exception as exc:
            _handle_gemini_error(exc, self._model_name)
            raise


# ── Helpers ────────────────────────────────────────────────────────────────────


def _extract_text(response: object) -> str:
    """Extract text content from a Gemini response object."""
    try:
        text = getattr(response, "text", None)
        if text is not None:
            return str(text)
    except (AttributeError, ValueError):
        pass

    # Fallback: iterate candidates → parts
    candidates = getattr(response, "candidates", None) or []
    if candidates:
        content = getattr(candidates[0], "content", None)
        parts = getattr(content, "parts", None) or []
        return "".join(getattr(p, "text", "") or "" for p in parts)

    return ""


def _handle_gemini_error(exc: Exception, model_name: str) -> None:
    """Map Gemini SDK errors to domain error types.

    Attempts to import google.genai.errors for exact matching; falls back to
    string inspection so the caller is protected even if the SDK changes names.
    """
    # Try exact exception class matching first.
    try:
        from google.genai import errors as genai_errors  # type: ignore[import-untyped]

        if isinstance(exc, genai_errors.ClientError):
            status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
            if status == 429 or "resource_exhausted" in str(exc).lower():
                raise LLMRateLimitError() from exc
            if status in (402, 403):
                raise LLMQuotaExhaustedError(deployment=model_name) from exc
            return  # other 4xx — re-raise as-is
        if isinstance(exc, genai_errors.ServerError):
            return  # 5xx — re-raise as-is
    except ImportError:
        pass

    # String-based fallback for SDK version mismatches.
    exc_str = str(exc).lower()
    if "resource_exhausted" in exc_str or "rate_limit" in exc_str or "429" in exc_str:
        raise LLMRateLimitError() from exc
    if "quota" in exc_str and ("403" in exc_str or "402" in exc_str):
        raise LLMQuotaExhaustedError(deployment=model_name) from exc
