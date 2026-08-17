"""
providers/factory.py
--------------------
Provider factory — reads the saved config and returns the correct
BaseProvider implementation.

This is the single point of dispatch for provider selection. The rest of
Raven never imports a concrete provider directly — everything goes through
get_provider(). This makes adding new providers a one-file change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from providers.base import BaseProvider

if TYPE_CHECKING:
    pass


def get_provider(config: dict) -> BaseProvider:
    """
    Instantiates and returns the correct provider based on the saved config.

    Args:
        config: The dict loaded from ConfigManager (config.json contents).

    Returns:
        A concrete BaseProvider implementation ready to use.

    Raises:
        ValueError: If the provider key is missing or unrecognized.
    """
    provider_key = config.get("provider", "").lower()
    model = config.get("model", "")
    api_key = config.get("api_key", "")

    if provider_key == "ollama":
        from providers.ollama import OllamaProvider
        return OllamaProvider(model=model or "qwen2.5:7b")

    if provider_key == "openai":
        from providers.openai import OpenAIProvider
        return OpenAIProvider(model=model or "gpt-4o-mini", api_key=api_key)

    if provider_key == "anthropic":
        from providers.anthropic import AnthropicProvider
        return AnthropicProvider(model=model or "claude-haiku-3-5", api_key=api_key)

    if provider_key == "gemini":
        from providers.gemini import GeminiProvider
        return GeminiProvider(model=model or "gemini-2.0-flash", api_key=api_key)

    if provider_key == "openrouter":
        from providers.openrouter import OpenRouterProvider
        return OpenRouterProvider(
            model=model or "anthropic/claude-haiku-3-5",
            api_key=api_key,
        )

    raise ValueError(
        f"Unknown provider '{provider_key}'. "
        "Valid options: ollama, openai, anthropic, gemini, openrouter"
    )


# Human-readable names for display in the wizard
PROVIDER_DISPLAY_NAMES = {
    "ollama":      "Ollama (Local — no API key required)",
    "openai":      "OpenAI (GPT-4o, GPT-3.5, etc.)",
    "anthropic":   "Anthropic (Claude Opus, Sonnet, Haiku)",
    "gemini":      "Google Gemini (Gemini 2.5 Pro, Flash)",
    "openrouter":  "OpenRouter (Access 100+ models via one key)",
}

# Ordered list for the wizard's numbered menu
PROVIDER_KEYS = ["ollama", "openai", "anthropic", "gemini", "openrouter"]
