"""
providers/ollama.py
-------------------
Ollama local provider implementation.

Ollama runs models locally — no API key required, no data leaves the machine.
This is the default provider and the only one that requires a running daemon.

Differences from the old LLMClient:
  - Implements BaseProvider interface
  - Adds list_models() for the setup wizard's model selection step
  - Model name is injected at construction time (from config) instead of hardcoded
  - Error messages route through a structured return path, not raw print()
"""

from __future__ import annotations

from typing import List

from providers.base import BaseProvider

# Default model used if config has no model specified
_DEFAULT_MODEL = "qwen2.5:7b"


class OllamaProvider(BaseProvider):
    """
    Sends prompts to a locally running Ollama instance.

    Requires:
      - Ollama installed and running (https://ollama.com)
      - The configured model downloaded: `ollama pull <model>`
    """

    def __init__(self, model: str = _DEFAULT_MODEL) -> None:
        self._model = model
        # Lazy import: avoids import error if ollama SDK isn't installed
        try:
            import ollama as _ollama_sdk
            self._client = _ollama_sdk.Client()
            self._sdk_available = True
        except ImportError:
            self._client = None
            self._sdk_available = False

    # ── BaseProvider interface ────────────────────────────────────────────────

    def analyze(self, system_prompt: str, user_message: str) -> str:
        """Sends prompt to Ollama and returns the model's response text."""
        if not self._sdk_available or self._client is None:
            return ""
        try:
            response = self._client.chat(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_message},
                ],
                options={"temperature": 0.1},
            )
            return response["message"]["content"]
        except Exception as e:
            print(f"  [Ollama] Error querying '{self._model}': {e}")
            return ""

    def is_available(self) -> bool:
        """Returns True if Ollama is running and the model is downloaded."""
        if not self._sdk_available or self._client is None:
            return False
        try:
            models = self._client.list()
            # Handle both old dict-based and new object-based SDK responses
            model_list = models.get("models", []) if isinstance(models, dict) else getattr(models, "models", [])
            available = []
            for m in model_list:
                name = m["model"] if isinstance(m, dict) else getattr(m, "model", str(m))
                available.append(name)
            return self._model in available
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """Returns names of all models currently installed in Ollama."""
        if not self._sdk_available or self._client is None:
            return []
        try:
            models = self._client.list()
            model_list = models.get("models", []) if isinstance(models, dict) else getattr(models, "models", [])
            result = []
            for m in model_list:
                name = m["model"] if isinstance(m, dict) else getattr(m, "model", str(m))
                result.append(name)
            return result
        except Exception:
            return []

    @property
    def provider_name(self) -> str:
        return "Ollama"

    @property
    def model_name(self) -> str:
        return self._model
