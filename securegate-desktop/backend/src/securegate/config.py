"""Configuration."""

import os


class Settings:
    """SecureGate settings (env vars or defaults)."""

    @property
    def detectors(self) -> str:
        return os.environ.get(
            "SECUREGATE_DETECTORS",
            "pattern,prompt_injection,ner,semantic,llm_classifier",
        )

    @property
    def lite_mode(self) -> bool:
        val = os.environ.get("SECUREGATE_LITE_MODE", "true").lower()
        return val in ("1", "true", "yes")

    @property
    def spacy_model(self) -> str:
        """spaCy model for NER (e.g. en_core_web_sm for ~12MB RAM, en_core_web_lg for better accuracy)."""
        return os.environ.get("SECUREGATE_SPACY_MODEL", "en_core_web_lg").strip() or "en_core_web_lg"

    # --- Pluggable LLM backend: local | gemini | self_hosted ---
    @property
    def llm_backend(self) -> str:
        """Which LLM to use for classifier and chat: local (BART/OpenAI), gemini, or self_hosted."""
        return (os.environ.get("SECUREGATE_LLM_BACKEND", "local") or "local").strip().lower()

    @property
    def gemini_api_key(self) -> str:
        return (os.environ.get("GEMINI_API_KEY") or os.environ.get("SECUREGATE_GEMINI_API_KEY") or "").strip()

    @property
    def llm_base_url(self) -> str:
        """Self-hosted or OpenAI-compatible base URL (e.g. https://your-llm/v1)."""
        return (os.environ.get("SECUREGATE_LLM_BASE_URL") or "").strip()

    @property
    def llm_api_key(self) -> str:
        """API key for self-hosted (or OpenAI when backend=local)."""
        return (os.environ.get("SECUREGATE_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or "").strip()

    @property
    def llm_model(self) -> str:
        """Model name for gemini/self_hosted (e.g. gemini-2.0-flash, gemini-3-flash-preview)."""
        return (os.environ.get("SECUREGATE_LLM_MODEL") or "gemini-2.0-flash").strip()
