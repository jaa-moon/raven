"""
providers/anthropic.py
----------------------
Anthropic (Claude) cloud provider implementation.

Uses the official `anthropic` Python SDK. Optional dependency — only
imported at runtime. If not installed, reports unavailable.

Supported models (curated list for the setup wizard):
  claude-opus-4-5, claude-sonnet-4-5, claude-haiku-3-5
"""

from __future__ import annotations

from typing import List

from providers.base import BaseProvider

_CURATED_MODELS = [
    "claude-3-5-sonnet-latest",
    "claude-3-5-haiku-latest",
    "claude-3-opus-latest",
]

_SDK_INSTALL_HINT = "Run: pip install anthropic"

# Anthropic uses a different message structure: content goes in user turn,
# system is a top-level parameter (not a message role).
_MAX_TOKENS = 4096


class AnthropicProvider(BaseProvider):
    """
    Sends prompts to Anthropic's Messages API.

    Requires:
      - `pip install anthropic`
      - A valid Anthropic API key in config
    """

    def __init__(self, model: str = "claude-3-5-haiku-latest", api_key: str = "") -> None:
        self._model = model
        self._api_key = api_key

    def _get_client(self):
        """Lazily imports and returns an Anthropic client, or None on failure."""
        try:
            import anthropic
            return anthropic.Anthropic(api_key=self._api_key)
        except ImportError:
            print(f"  [Anthropic] SDK not installed. {_SDK_INSTALL_HINT}")
            return None
        except Exception as e:
            print(f"  [Anthropic] Client init failed: {e}")
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
                response = client.messages.create(
                    model=self._model,
                    max_tokens=_MAX_TOKENS,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_message},
                    ],
                )
                if response.content:
                    return response.content[0].text
                return ""
            except Exception as e:
                # If it's a rate limit error (429) or internal server error (500+), retry.
                # In anthropic SDK, errors usually have a status_code
                status_code = getattr(e, 'status_code', None)
                if status_code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    print(f"  [Anthropic] Rate limited or server error ({status_code}). Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                
                print(f"  [Anthropic] Error querying '{self._model}': {e}")
                return ""
        
        return ""

    def is_available(self) -> bool:
        """Validates by sending a minimal test message."""
        client = self._get_client()
        if client is None:
            return False
        try:
            client.messages.create(
                model=self._model,
                max_tokens=1,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception:
            return False

    def list_models(self) -> List[str]:
        return _CURATED_MODELS

    @property
    def provider_name(self) -> str:
        return "Anthropic"

    @property
    def model_name(self) -> str:
        return self._model
