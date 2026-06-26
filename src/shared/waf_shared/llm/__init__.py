"""LLM provider abstractions — protocol, factory, and provider implementations.

Provider selection is driven by LLM_PROVIDER (default: "gemini"):
  gemini — Google Gemini via google-genai  [recommended, no Azure required]
  azure  — Azure OpenAI via openai SDK     [enterprise path]

Use create_llm_provider() from factory.py to get the right backend.
"""
