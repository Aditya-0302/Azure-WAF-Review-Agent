"""Reasoning Agent runtime configuration.

Inherits platform settings (DB_*, SERVICEBUS_NAMESPACE, KEYVAULT_URI) from
AgentSettings.

LLM provider selection (LLM_PROVIDER):
  gemini  — Google Gemini [default, recommended for local development]
  azure   — Azure OpenAI  [enterprise path]

Gemini variables (required when LLM_PROVIDER=gemini):
  GEMINI_API_KEY       — API key from https://aistudio.google.com/app/apikey
  GEMINI_CHAT_MODEL    — model name (default "gemini-2.5-pro")
  GEMINI_EMBED_MODEL   — embedding model (default "text-embedding-004")

Azure OpenAI variables (required when LLM_PROVIDER=azure):
  AZURE_OPENAI_ENDPOINT        — Azure OpenAI service endpoint URL
  AZURE_OPENAI_API_VERSION     — REST API version (default "2024-10-21")
  AZURE_OPENAI_DEPLOYMENT_CHAT — pinned deployment name; never use "latest"

Shared LLM tuning (both providers):
  AZURE_OPENAI_MAX_TOKENS — token budget per prompt (default 4096)
  LLM_TEMPERATURE         — sampling temperature (default 0.1)
"""

from __future__ import annotations

from pydantic import Field, SecretStr, model_validator

from waf_shared.agents.settings import AgentSettings

_SUPPORTED_PROVIDERS = frozenset({"gemini", "azure"})


class ReasoningConfig(AgentSettings):
    # ── LLM provider selection ────────────────────────────────────────────────
    llm_provider: str = "gemini"  # "gemini" | "azure"

    # ── Gemini settings ───────────────────────────────────────────────────────
    gemini_api_key: SecretStr | None = None
    gemini_chat_model: str = "gemini-2.5-pro"
    gemini_embed_model: str = "text-embedding-004"

    # ── Azure OpenAI settings (optional; only required when llm_provider=azure)
    azure_openai_endpoint: str = ""
    azure_openai_api_version: str = "2024-10-21"
    azure_openai_deployment_chat: str = ""  # must be pinned; never "latest"

    # ── Shared LLM tuning ─────────────────────────────────────────────────────
    azure_openai_max_tokens: int = Field(default=4096, ge=1)
    llm_temperature: float = Field(default=0.1, ge=0.0, le=2.0)

    @model_validator(mode="after")
    def validate_llm_provider(self) -> "ReasoningConfig":
        p = self.llm_provider.lower().strip()
        if p not in _SUPPORTED_PROVIDERS:
            raise ValueError(
                f"LLM_PROVIDER '{self.llm_provider}' is not supported. "
                f"Choose one of: {', '.join(sorted(_SUPPORTED_PROVIDERS))}"
            )
        if p == "gemini" and (
            self.gemini_api_key is None
            or not self.gemini_api_key.get_secret_value()
        ):
            raise ValueError(
                "GEMINI_API_KEY is required when LLM_PROVIDER=gemini. "
                "Get a free API key at https://aistudio.google.com/app/apikey"
            )
        if p == "azure" and not self.azure_openai_endpoint:
            raise ValueError(
                "AZURE_OPENAI_ENDPOINT is required when LLM_PROVIDER=azure"
            )
        if p == "azure" and not self.azure_openai_deployment_chat:
            raise ValueError(
                "AZURE_OPENAI_DEPLOYMENT_CHAT is required when LLM_PROVIDER=azure"
            )
        return self
