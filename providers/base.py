"""
providers/base.py
-----------------
Abstract base class for all LLM provider implementations.

Design rationale
----------------
Every provider — whether local (Ollama) or cloud (OpenAI, Anthropic, Gemini,
OpenRouter) — must expose the same method contract:

  analyze()        → send a prompt, get back text (synchronous)
  analyze_async()  → async wrapper around analyze() using asyncio.to_thread
  is_available()   → pre-flight check before a long scan
  list_models()    → for Ollama; cloud providers return a static curated list
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import List


class BaseProvider(ABC):
    """
    Abstract contract that every LLM provider must satisfy.
    """

    @abstractmethod
    def analyze(self, system_prompt: str, user_message: str) -> str:
        """
        Send a chat request to the provider and return the assistant's text.
        """
        ...

    async def analyze_async(self, system_prompt: str, user_message: str) -> str:
        """
        Asynchronous wrapper around analyze() to prevent blocking event loops.
        """
        return await asyncio.to_thread(self.analyze, system_prompt, user_message)

    @abstractmethod
    def is_available(self) -> bool:
        """
        Returns True if the provider + model are reachable and ready.
        """
        ...

    @abstractmethod
    def list_models(self) -> List[str]:
        """
        Returns a list of model names available for this provider.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name, e.g. 'Ollama', 'OpenAI'."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Currently configured model name, e.g. 'qwen2.5:7b', 'gpt-4o'."""
        ...
