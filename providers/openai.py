"""
providers/openai.py
-------------------
OpenAI cloud provider implementation.

Uses the official `openai` Python SDK (>=1.0). The SDK is NOT a hard
dependency of Raven — it is only imported at runtime inside methods.
If not installed, the provider reports itself as unavailable and prompts
the user to install it.

Supported models (curated list for the setup wizard):
  gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo
"""

from __future__ import annotations

from typing import List

from providers.base import BaseProvider

_CURATED_MODELS = [
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
]

_SDK_INSTALL_HINT = "Run: pip install openai"


class OpenAIProvider(BaseProvider):
    """
    Sends prompts to OpenAI's chat completions API.

    Requires:
      - `pip install openai`
      - A valid API key in config (OPENAI_API_KEY or config.api_key)
    """

    def __init__(self, model: str = "gpt-4o-mini", api_key: str = "") -> None:
        self._model = model
        self._api_key = api_key

    def _get_client(self):
        """Lazily imports and returns an OpenAI client, or None on failure."""
        try:
            from openai import OpenAI
            return OpenAI(api_key=self._api_key)
        except ImportError:
            print(f"  [OpenAI] SDK not installed. {_SDK_INSTALL_HINT}")
            return None
        except Exception as e:
            print(f"  [OpenAI] Client init failed: {e}")
            return None

    def analyze(self, system_prompt: str, user_message: str) -> str:
        import time
        client = self._get_client()
        if client is None:
            return ""
            
        max_retries = 3
        base_delay = 2.0
        
        for attempt in range(max_retries):
            try:
                response = client.chat.completions.create(
                    model=self._model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_message},
                    ],
                    temperature=0.1,
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                status_code = getattr(e, 'status_code', None)
                error_name = type(e).__name__
                
                is_retryable = (
                    status_code in (429, 500, 502, 503, 504) or
                    error_name in ("RateLimitError", "InternalServerError", "APIConnectionError")
                )
                
                if is_retryable and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    print(f"  [OpenAI] Rate limited or server error ({error_name}/{status_code}). Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                    
                print(f"  [OpenAI] Error querying '{self._model}': {e}")
                return ""
        return ""

    def is_available(self) -> bool:
        """Validates the API key by listing models (lightweight API call)."""
        client = self._get_client()
        if client is None:
            return False
        try:
            client.models.list()
            return True
        except Exception:
            return False

    def list_models(self) -> List[str]:
        return _CURATED_MODELS

    @property
    def provider_name(self) -> str:
        return "OpenAI"

    @property
    def model_name(self) -> str:
        return self._model
