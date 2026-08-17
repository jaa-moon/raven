"""
providers/gemini.py
-------------------
Google Gemini cloud provider implementation.

Uses the `google-generativeai` Python SDK. Optional dependency — only
imported at runtime. If not installed, reports unavailable.

Note on prompt structure: Gemini's GenerativeModel.generate_content() does
not natively support a "system" role in the same way as OpenAI. We prepend
the system prompt as the first "user" turn with a model "OK" acknowledgment
(the recommended pattern from Google's docs for simulating system prompts
with the Python SDK's start_chat() method).

Supported models (curated list for the setup wizard):
  gemini-2.5-pro, gemini-2.0-flash, gemini-1.5-flash
"""

from __future__ import annotations

from typing import List

from providers.base import BaseProvider

_CURATED_MODELS = [
    "gemini-2.5-pro",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
]

_SDK_INSTALL_HINT = "Run: pip install google-generativeai"


class GeminiProvider(BaseProvider):
    """
    Sends prompts to Google's Gemini API via google-generativeai SDK.

    Requires:
      - `pip install google-generativeai`
      - A valid Google AI Studio API key in config
    """

    def __init__(self, model: str = "gemini-2.0-flash", api_key: str = "") -> None:
        self._model = model
        self._api_key = api_key

    def _configure_sdk(self) -> bool:
        """Configures the Gemini SDK with the API key. Returns False on failure."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self._api_key)
            return True
        except ImportError:
            print(f"  [Gemini] SDK not installed. {_SDK_INSTALL_HINT}")
            return False
        except Exception as e:
            print(f"  [Gemini] SDK configuration failed: {e}")
            return False

    def analyze(self, system_prompt: str, user_message: str) -> str:
        import time
        if not self._configure_sdk():
            return ""
        
        max_retries = 3
        base_delay = 2.0
        
        for attempt in range(max_retries):
            try:
                import google.generativeai as genai
                from google.api_core.exceptions import RetryError, ResourceExhausted, InternalServerError, ServiceUnavailable

                # Use system_instruction parameter (available in SDK >= 0.5)
                model = genai.GenerativeModel(
                    model_name=self._model,
                    system_instruction=system_prompt,
                    generation_config=genai.GenerationConfig(temperature=0.1),
                )
                response = model.generate_content(user_message)
                return response.text or ""
            except Exception as e:
                # Check for rate limits and server errors
                error_str = str(e).lower()
                is_retryable = (
                    "429" in error_str or 
                    "resourceexhausted" in error_str or 
                    "500" in error_str or 
                    "503" in error_str or 
                    "serviceunavailable" in error_str or
                    "internalservererror" in error_str
                )
                
                if is_retryable and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    print(f"  [Gemini] Rate limited or server error. Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                    
                print(f"  [Gemini] Error querying '{self._model}': {e}")
                return ""
        
        return ""

    def is_available(self) -> bool:
        """Validates by listing available models (lightweight API call)."""
        if not self._configure_sdk():
            return False
        try:
            import google.generativeai as genai
            list(genai.list_models())
            return True
        except Exception:
            return False

    def list_models(self) -> List[str]:
        return _CURATED_MODELS

    @property
    def provider_name(self) -> str:
        return "Gemini"

    @property
    def model_name(self) -> str:
        return self._model
