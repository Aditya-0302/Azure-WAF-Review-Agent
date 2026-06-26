"""Azure OpenAI LLM provider — enterprise implementation of LLMProvider.

Authentication:
- Production: pass ``credential`` (WorkloadIdentityCredential / ManagedIdentity);
  the adapter exchanges it for a Cognitive Services bearer token.
- Tests / local: pass ``api_key`` directly.

Exactly one of (api_key, credential) must be provided.

This provider is the *enterprise / Azure-native* path. For local development or
when Azure OpenAI is unavailable, use GeminiProvider instead (LLM_PROVIDER=gemini).

Model deployment is pinned at construction; callers must never pass "latest"
as the deployment name.
"""

from __future__ import annotations

from typing import Any

from openai import APIStatusError, AsyncAzureOpenAI, RateLimitError

from waf_shared.domain.errors.infrastructure_errors import (
    LLMQuotaExhaustedError,
    LLMRateLimitError,
)
from waf_shared.llm.provider import LLMResponse


class AzureOpenAIProvider:
    """Implements :class:`LLMProvider` against an Azure OpenAI deployment.

    The ``deployment_name`` must be a specific, pinned deployment (e.g.
    ``"gpt-4o-2024-11-20"``), not the ``"latest"`` alias.
    """

    def __init__(
        self,
        *,
        azure_endpoint: str,
        api_version: str,
        deployment_name: str,
        api_key: str | None = None,
        credential: Any | None = None,
    ) -> None:
        if api_key is None and credential is None:
            raise ValueError("Provide either api_key or credential")
        if api_key is not None and credential is not None:
            raise ValueError("Provide exactly one of api_key or credential, not both")
        if "latest" in deployment_name.lower():
            raise ValueError(
                f"Deployment name '{deployment_name}' looks like an alias. "
                "Pin a specific deployment per ISSUE-L07."
            )

        self._deployment = deployment_name

        if api_key is not None:
            self._client = AsyncAzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_version=api_version,
                api_key=api_key,
            )
        else:
            from azure.identity.aio import get_bearer_token_provider  # type: ignore[import-untyped]

            token_provider = get_bearer_token_provider(
                credential,
                "https://cognitiveservices.azure.com/.default",
            )
            self._client = AsyncAzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_version=api_version,
                azure_ad_token_provider=token_provider,
            )

    def model_id(self) -> str:
        return self._deployment

    async def chat_complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> LLMResponse:
        try:
            response = await self._client.chat.completions.create(
                model=self._deployment,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                response_format={"type": "json_object"},
                timeout=60.0,
            )
        except RateLimitError as exc:
            raise LLMRateLimitError(retry_after_seconds=_parse_retry_after(exc)) from exc
        except APIStatusError as exc:
            if exc.status_code == 429:  # noqa: PLR2004
                raise LLMRateLimitError(retry_after_seconds=_parse_retry_after(exc)) from exc
            if exc.status_code in (402, 403):  # noqa: PLR2004
                raise LLMQuotaExhaustedError(deployment=self._deployment) from exc
            raise

        choice = response.choices[0]
        usage = response.usage
        return LLMResponse(
            content=choice.message.content or "",
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            model=response.model or self._deployment,
        )

    def count_tokens(self, text: str) -> int:
        """Estimate token count.

        Uses tiktoken if available (exact); falls back to the 4-chars-per-token
        heuristic so the optional dependency never blocks startup.
        """
        try:
            import tiktoken  # type: ignore[import-untyped]

            enc = tiktoken.encoding_for_model("gpt-4o")
            return len(enc.encode(text))
        except Exception:
            return max(1, len(text) // 4)

    async def healthcheck(self) -> None:
        """Verify API connectivity with a minimal completion call."""
        try:
            await self._client.chat.completions.create(
                model=self._deployment,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
                timeout=15.0,
            )
        except RateLimitError as exc:
            raise LLMRateLimitError(retry_after_seconds=_parse_retry_after(exc)) from exc
        except APIStatusError as exc:
            if exc.status_code == 429:  # noqa: PLR2004
                raise LLMRateLimitError(retry_after_seconds=_parse_retry_after(exc)) from exc
            if exc.status_code in (402, 403):  # noqa: PLR2004
                raise LLMQuotaExhaustedError(deployment=self._deployment) from exc
            raise


def _parse_retry_after(exc: Exception) -> int | None:
    response = getattr(exc, "response", None)
    headers: dict[str, str] = getattr(response, "headers", {}) or {}
    ra = headers.get("Retry-After") or headers.get("retry-after")
    if ra:
        try:
            return int(ra)
        except (ValueError, TypeError):
            pass
    return None
