"""
intelligence/llm.py
-------------------
One interface to language models. The rest of Raven never touches a
provider directly: it asks `LLM.ask_json()` and gets validated data or None.

Deterministic controls (scope, budget, schemas, tool validation) never depend
on this module; when no model is available every caller has a rule-based path.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional

from core.budget import BudgetManager

logger = logging.getLogger("raven.llm")

LOCAL_PROVIDERS = {"ollama"}


class LLM:
    """Wraps a `providers.base.BaseProvider` (local or API) with budget accounting."""

    def __init__(self, provider: Any = None, budget: Optional[BudgetManager] = None) -> None:
        self.provider = provider
        self.budget = budget

    @classmethod
    def from_config(cls, config: Optional[Dict[str, Any]], budget: Optional[BudgetManager] = None) -> "LLM":
        if not config or not config.get("provider"):
            return cls(None, budget)
        try:
            from providers.factory import get_provider
            return cls(get_provider(config), budget)
        except Exception as e:
            logger.info("LLM provider unavailable (%s); running rule-based.", e)
            return cls(None, budget)

    @property
    def available(self) -> bool:
        if self.provider is None:
            return False
        try:
            return bool(self.provider.is_available())
        except Exception:
            return False

    @property
    def kind(self) -> str:
        if self.provider is None:
            return "none"
        name = str(getattr(self.provider, "provider_name", "")).lower()
        return "local" if any(p in name for p in LOCAL_PROVIDERS) else "api"

    def describe(self) -> str:
        if self.provider is None:
            return "none (rule-based mode)"
        return f"{self.kind}: {self.provider.provider_name} / {self.provider.model_name}"

    async def ask(self, system: str, user: str) -> Optional[str]:
        if not self.available or (self.budget and not self.budget.can_afford(llm=True)):
            return None
        if self.budget:
            self.budget.consume(llm_calls=1)
        try:
            return await self.provider.analyze_async(system, user)
        except Exception as e:
            logger.info("LLM call failed: %s", e)
            return None

    async def ask_json(self, system: str, user: str) -> Optional[Dict[str, Any]]:
        raw = await self.ask(system + "\nRespond with a single JSON object and nothing else.", user)
        return extract_json(raw) if raw else None


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Pull the first JSON object out of a model reply (handles ``` fences)."""
    if not text:
        return None
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            try:
                obj = json.loads(text[start:i + 1])
                return obj if isinstance(obj, dict) else None
            except json.JSONDecodeError:
                return None
    return None
