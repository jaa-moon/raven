"""
raven_mcp/gateway.py
--------------------
The controlled tool-access layer. Agents never call tools directly:

    Agent -> Gateway -> (resolve tool) -> validate args -> ScopeValidator
          -> Budget -> execute (timeout) -> normalize -> log -> ToolResult
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.budget import BudgetManager
from core.models import ToolCallRecord, ToolRequest, ToolResult
from core.scope import ScopeValidator
from raven_mcp.models import ToolDefinition, ToolError, validate_arguments
from raven_mcp.registry import ToolRegistry

logger = logging.getLogger("raven.gateway")

CallLogger = Callable[[ToolCallRecord], None]


class Gateway:
    def __init__(
        self,
        registry: ToolRegistry,
        scope: ScopeValidator,
        budget: BudgetManager,
        target_type: Optional[str] = None,
        on_call: Optional[CallLogger] = None,
    ) -> None:
        self.registry = registry
        self.scope = scope
        self.budget = budget
        self.target_type = target_type
        self._on_call = on_call
        self.calls: List[ToolCallRecord] = []

    # -- discovery / selection support ---------------------------------------------

    def discover(self, capability: Optional[str] = None) -> List[Dict[str, Any]]:
        if capability:
            return [t.summary() for t in self.registry.providers(capability, self.target_type)]
        return self.registry.describe()

    def can_provide(self, capability: str) -> bool:
        return bool(self.registry.providers(capability, self.target_type))

    def alternatives(self, capability: str, exclude: List[str]) -> List[str]:
        return [t.name for t in self.registry.providers(capability, self.target_type, exclude)]

    # -- execution ------------------------------------------------------------------

    async def execute(self, req: ToolRequest) -> ToolResult:
        started = time.monotonic()
        tool, err = self._resolve(req)
        if tool is None:
            return self._finish(req, None, ToolResult(
                request_id=req.request_id, capability=req.capability,
                status="tool_unavailable", error=err), started)

        args, problems = validate_arguments(tool, req.arguments)
        if problems:
            return self._finish(req, tool, ToolResult(
                request_id=req.request_id, tool=tool.name, capability=req.capability,
                status="invalid_args", error="; ".join(problems)), started)

        decision = self.scope.check(self._scope_targets(tool, args), tool.risk_level)
        if not decision.allowed:
            return self._finish(req, tool, ToolResult(
                request_id=req.request_id, tool=tool.name, capability=req.capability,
                status="out_of_scope", error=decision.reason), started)

        if not self.budget.can_afford(expensive=tool.expensive):
            return self._finish(req, tool, ToolResult(
                request_id=req.request_id, tool=tool.name, capability=req.capability,
                status="budget_exhausted",
                error=f"Budget exhausted ({', '.join(self.budget.exhausted_dimensions()) or 'limit reached'})."),
                started)

        self.budget.consume(tool_calls=1, expensive=1 if tool.expensive else 0)
        result = await self._run(tool, req, args)
        return self._finish(req, tool, result, started)

    # -- internals ------------------------------------------------------------------

    def _resolve(self, req: ToolRequest) -> Tuple[Optional[ToolDefinition], str]:
        if req.tool:
            tool = self.registry.get(req.tool)
            if tool is None:
                return None, f"Unknown tool '{req.tool}'."
            missing = tool.missing_requirements()
            return (None, f"Tool '{tool.name}' unavailable; missing {', '.join(missing)}.") if missing else (tool, "")
        providers = self.registry.providers(req.capability, self.target_type, req.exclude_tools)
        if providers:
            return providers[0], ""
        return None, self.registry.missing_capability_reason(req.capability)

    @staticmethod
    def _scope_targets(tool: ToolDefinition, args: Dict[str, Any]) -> List[Tuple[str, str]]:
        targets = []
        for arg, kind in tool.scope_args.items():
            if arg in args and args[arg] not in (None, ""):
                targets.append((kind, str(args[arg])))
        return targets

    async def _run(self, tool: ToolDefinition, req: ToolRequest, args: Dict[str, Any]) -> ToolResult:
        handler = tool.handler
        base = dict(request_id=req.request_id, tool=tool.name, capability=req.capability)
        try:
            if inspect.iscoroutinefunction(handler):
                raw = await asyncio.wait_for(handler(**args), timeout=tool.timeout_seconds)
            else:
                loop = asyncio.get_running_loop()
                raw = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: handler(**args)), timeout=tool.timeout_seconds)
        except asyncio.TimeoutError:
            return ToolResult(**base, status="timeout", error=f"Timed out after {tool.timeout_seconds:g}s.")
        except ToolError as e:
            return ToolResult(**base, status=e.status, error=e.message)  # type: ignore[arg-type]
        except Exception as e:  # tool crash: contained, classified, recoverable
            logger.debug("Tool %s crashed", tool.name, exc_info=True)
            return ToolResult(**base, status="error", error=f"{type(e).__name__}: {e}")
        return ToolResult(**base, status="ok", data=self._normalize(raw))

    @staticmethod
    def _normalize(raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if hasattr(raw, "model_dump"):
            return raw.model_dump()
        if isinstance(raw, (list, tuple)):
            return {"items": list(raw)}
        return {"result": raw}

    def _finish(self, req: ToolRequest, tool: Optional[ToolDefinition],
                result: ToolResult, started: float) -> ToolResult:
        result.duration_ms = round((time.monotonic() - started) * 1000, 2)
        record = ToolCallRecord(
            request_id=req.request_id, tool=result.tool, capability=req.capability,
            agent=req.agent, task_id=req.task_id, status=result.status,
            duration_ms=result.duration_ms, error=result.error[:300], purpose=req.purpose,
        )
        self.calls.append(record)
        if self._on_call:
            self._on_call(record)
        return result
