"""LLM provider factory — instantiates the correct backend from configuration.

Supported providers (LLM_PROVIDER env var):
  gemini  — Google Gemini via google-genai SDK  [default, recommended]
  azure   — Azure OpenAI via openai SDK          [enterprise path]

Usage:
    from waf_shared.llm.factory import create_llm_provider

    provider = create_llm_provider(
        provider="gemini",
        gemini_api_key="AIza...",
        gemini_chat_model="gemini-2.5-pro",
    )

Adding a new provider:
    1. Implement the LLMProvider protocol in a new module under waf_shared/llm/.
    2. Add a branch here.
    3. No other file needs to change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from waf_shared.llm.provider import LLMProvider

_SUPPORTED_PROVIDERS = ("gemini", "azure")


def create_llm_provider(
    *,
    provider: str,
    # ── Gemini settings ───────────────────────────────────────────────────────
    gemini_api_key: str = "",
    gemini_chat_model: str = "gemini-2.5-pro",
    # ── Azure OpenAI settings ─────────────────────────────────────────────────
    azure_openai_endpoint: str = "",
    azure_openai_api_version: str = "2024-10-21",
    azure_openai_deployment_chat: str = "",
    azure_openai_api_key: str | None = None,
    azure_openai_credential: Any | None = None,
) -> "LLMProvider":
    """Instantiate and return the configured LLM provider.

    Args:
        provider: ``"gemini"`` or ``"azure"`` (case-insensitive).
        gemini_api_key: Required when provider is ``"gemini"``.
        gemini_chat_model: Gemini model name; default ``"gemini-2.5-pro"``.
        azure_openai_endpoint: Required when provider is ``"azure"``.
        azure_openai_api_version: Azure OpenAI REST API version.
        azure_openai_deployment_chat: Pinned deployment name; required for ``"azure"``.
        azure_openai_api_key: API key auth (local/CI use).
        azure_openai_credential: Credential object for managed-identity auth.

    Returns:
        A concrete implementation of :class:`~waf_shared.llm.provider.LLMProvider`.

    Raises:
        ValueError: If the provider is unknown or required settings are missing.
    """
    p = provider.lower().strip()

    if p == "gemini":
        if not gemini_api_key:
            raise ValueError(
                "GEMINI_API_KEY is required when LLM_PROVIDER=gemini. "
                "Get a free API key at https://aistudio.google.com/app/apikey"
            )
        from waf_shared.llm.gemini_provider import GeminiProvider

        return GeminiProvider(
            api_key=gemini_api_key,
            model_name=gemini_chat_model,
        )

    if p == "azure":
        if not azure_openai_endpoint:
            raise ValueError(
                "AZURE_OPENAI_ENDPOINT is required when LLM_PROVIDER=azure"
            )
        if not azure_openai_deployment_chat:
            raise ValueError(
                "AZURE_OPENAI_DEPLOYMENT_CHAT is required when LLM_PROVIDER=azure"
            )
        if azure_openai_api_key is None and azure_openai_credential is None:
            raise ValueError(
                "Either AZURE_OPENAI_API_KEY or a credential must be provided "
                "when LLM_PROVIDER=azure"
            )
        from waf_shared.llm.azure_openai import AzureOpenAIProvider

        return AzureOpenAIProvider(
            azure_endpoint=azure_openai_endpoint,
            api_version=azure_openai_api_version,
            deployment_name=azure_openai_deployment_chat,
            api_key=azure_openai_api_key,
            credential=azure_openai_credential,
        )

    raise ValueError(
        f"Unknown LLM_PROVIDER '{provider}'. "
        f"Supported values: {', '.join(_SUPPORTED_PROVIDERS)}."
    )
