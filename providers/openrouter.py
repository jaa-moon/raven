"""
providers/openrouter.py
-----------------------
OpenRouter cloud provider implementation.

OpenRouter is a unified API gateway that routes requests to hundreds of
models (Claude, GPT-4o, Llama, Mistral, Gemini, etc.) through a single
OpenAI-compatible endpoint.

Why httpx instead of the OpenRouter SDK?
OpenRouter's API is 100% OpenAI-compatible. We use the `openai` SDK pointed
at OpenRouter's base URL instead of a separate dependency. Falls back to raw
httpx if openai SDK is not installed.

Supported models (curated list for setup wizard):
  anthropic/claude-sonnet-4-5
  anthropic/claude-haiku-3-5
  openai/gpt-4o
  openai/gpt-4o-mini
  meta-llama/llama-3.3-70b-instruct
  google/gemini-flash-1.5
  mistralai/mistral-7b-instruct
"""

from __future__ import annotations

from typing import List

from providers.base import BaseProvider

_BASE_URL = "https://openrouter.ai/api/v1"

_CURATED_MODELS = [
    "anthropic/claude-sonnet-4-5",
    "anthropic/claude-haiku-3-5",
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "meta-llama/llama-3.3-70b-instruct",
    "google/gemini-flash-1.5",
    "mistralai/mistral-7b-instruct",
]

_SDK_INSTALL_HINT = "Run: pip install openai  (OpenRouter uses OpenAI-compatible API)"


class OpenRouterProvider(BaseProvider):
    """
    Routes prompts through OpenRouter to any supported model.

    Requires:
      - `pip install openai`  (uses OpenAI SDK pointed at OpenRouter)
      - A valid OpenRouter API key from https://openrouter.ai
    """

    def __init__(
        self,
        model: str = "anthropic/claude-haiku-3-5",
        api_key: str = "",
    ) -> None:
        self._model = model
        self._api_key = api_key

    def _get_client(self):
        """Returns an OpenAI client pointed at OpenRouter, or None on failure."""
        try:
            from openai import OpenAI
            return OpenAI(
                api_key=self._api_key,
                base_url=_BASE_URL,
            )
        except ImportError:
            print(f"  [OpenRouter] OpenAI SDK not installed. {_SDK_INSTALL_HINT}")
            return None
        except Exception as e:
            print(f"  [OpenRouter] Client init failed: {e}")
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
                    extra_headers={
                        "HTTP-Referer": "https://github.com/raven-agent",
                        "X-Title": "Raven Security Scanner",
                    },
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
                    print(f"  [OpenRouter] Rate limited or server error ({error_name}/{status_code}). Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                    
                print(f"  [OpenRouter] Error querying '{self._model}': {e}")
                return ""
        return ""

    def is_available(self) -> bool:
        """Validates API key via a lightweight models list call."""
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
        return "OpenRouter"

    @property
    def model_name(self) -> str:
        return self._model
