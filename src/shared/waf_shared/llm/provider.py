"""LLMProvider protocol and LLMResponse data transfer object.

Defines the contract all LLM backends must satisfy.  Deterministic rule
evaluation never touches this — it is only used by the LLM-assisted pipeline.

Supported implementations:
  GeminiProvider    — Google Gemini (default / recommended)
  AzureOpenAIProvider — Azure OpenAI (enterprise path)

Use :func:`waf_shared.llm.factory.create_llm_provider` to instantiate the
correct backend from configuration rather than importing a provider directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class LLMResponse:
    """Structured response returned by every LLM provider implementation."""

    content: str
    prompt_tokens: int
    completion_tokens: int
    model: str

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol every LLM backend must implement.

    Implementers must:
    - Pin the model deployment name (never pass "latest" alias).
    - Raise LLMRateLimitError on HTTP 429.
    - Raise LLMQuotaExhaustedError on HTTP 402 / quota exceeded.
    - Always request JSON output format so the caller can parse the response.
    """

    def model_id(self) -> str:
        """Return the pinned model deployment identifier."""
        ...

    async def chat_complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> LLMResponse:
        """Send a chat completion and return a structured response.

        The implementation MUST request JSON output mode so the caller can
        reliably parse structured findings from the response content.
        """
        ...

    def count_tokens(self, text: str) -> int:
        """Estimate the token count for *text* without making an API call.

        Used to enforce the token budget before constructing prompts.
        """
        ...

    async def healthcheck(self) -> None:
        """Verify the provider is reachable and the credentials are valid.

        Makes a minimal API call (no billable reasoning).  Raises any exception
        if the provider is unreachable or misconfigured.
        """
        ...
