"""
raven_mcp/gateway.py
--------------------
Dual-purpose MCP gateway for Raven:

A) MCPGateway (existing) — routes tool calls to external MCP server
   subprocesses via ClientSession for external MCP client usage.

B) InternalGateway (NEW) — in-process tool dispatch for agent-to-tool
   routing. Resolves tools from ToolRegistry, calls them directly,
   logs every call for dashboard display.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from raven_mcp.tool_schema import ALL_TOOLS, ToolSchema


# ── Shared result model ──────────────────────────────────────────────────────

@dataclass
class ToolResult:
    """Result of a single tool invocation."""
    tool_name: str = ""
    success: bool = True
    data: Any = None
    error: str = ""
    duration_ms: float = 0.0


@dataclass
class ToolCallLog:
    """Log entry for a single gateway call (for dashboard display)."""
    tool_name: str
    params: Dict[str, Any]
    result: ToolResult
    timestamp: str = ""


# ── InternalGateway (NEW) ────────────────────────────────────────────────────

class InternalGateway:
    """
    In-process tool dispatch gateway.

    Agents call gateway.call(tool_name, **params) and the gateway:
    1. Resolves the tool from ToolRegistry
    2. Calls the function directly (sync or async)
    3. Wraps the result in ToolResult
    4. Logs the call for dashboard display
    """

    def __init__(self, registry) -> None:
        """
        Args:
            registry: A ToolRegistry instance with pre-imported tool modules.
        """
        self.registry = registry
        self._call_log: List[ToolCallLog] = []
        self._lock = threading.Lock()

    async def call(
        self,
        tool_name: str,
        timeout_seconds: int = 30,
        **params
    ) -> ToolResult:
        """
        Invoke a registered tool by name with keyword params.

        Handles both sync and async tool functions, applies a timeout,
        and catches all exceptions into ToolResult.
        """
        start = time.time()
        try:
            registered = self.registry.get(tool_name)
        except Exception as e:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error=str(e),
                duration_ms=0.0,
            )
            self._log_call(tool_name, params, result)
            return result

        fn = registered.get_callable()

        try:
            if inspect.iscoroutinefunction(fn):
                # Async tool function — await directly with timeout
                raw = await asyncio.wait_for(
                    fn(**params),
                    timeout=timeout_seconds,
                )
            else:
                # Sync tool function — run in executor with timeout
                loop = asyncio.get_running_loop()
                raw = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: fn(**params)),
                    timeout=timeout_seconds,
                )

            # Normalize result to dict
            if hasattr(raw, "dict"):
                output = raw.dict()
            elif hasattr(raw, "model_dump"):
                output = raw.model_dump()
            elif isinstance(raw, dict):
                output = raw
            elif isinstance(raw, (list, tuple)):
                output = {"items": raw}
            else:
                output = {"result": raw}

            result = ToolResult(
                tool_name=tool_name,
                success=True,
                data=output,
                duration_ms=(time.time() - start) * 1000,
            )

        except asyncio.TimeoutError:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Timeout after {timeout_seconds}s",
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error=str(e),
                duration_ms=(time.time() - start) * 1000,
            )

        self._log_call(tool_name, params, result)
        return result

    async def call_with_retry(
        self,
        tool_name: str,
        max_retries: int = 2,
        **params
    ) -> ToolResult:
        """Retry tool call on failure with linear backoff. Returns last result."""
        result = None
        for attempt in range(max_retries + 1):
            result = await self.call(tool_name, **params)
            if result.success:
                return result
            if attempt < max_retries:
                await asyncio.sleep(1.0 * (attempt + 1))
        return result  # type: ignore[return-value]

    def _log_call(self, tool_name: str, params: dict, result: ToolResult) -> None:
        """Thread-safe call logging for dashboard display."""
        # Truncate large param values for log readability
        safe_params = {}
        for k, v in params.items():
            s = str(v)
            safe_params[k] = s[:80] + "..." if len(s) > 80 else s

        entry = ToolCallLog(
            tool_name=tool_name,
            params=safe_params,
            result=result,
            timestamp=datetime.now().isoformat(),
        )
        with self._lock:
            self._call_log.append(entry)
            # Keep log bounded
            if len(self._call_log) > 200:
                self._call_log = self._call_log[-100:]

    def last_calls(self, n: int = 5) -> List[ToolCallLog]:
        """Return the last N tool call log entries (for dashboard)."""
        with self._lock:
            return list(self._call_log[-n:])

    def list_tools(self, group: Optional[str] = None) -> List[ToolSchema]:
        """List available tool schemas, optionally filtered by group."""
        if group:
            return self.registry.list_by_group(group)
        return self.registry.all_schemas()

    def total_calls(self) -> int:
        """Return total number of tool calls made."""
        with self._lock:
            return len(self._call_log)


# ── MCPGateway (existing, unchanged) ────────────────────────────────────────

class MCPGateway:
    """
    Routes tool calls from agents to external MCP server subprocesses.
    Used when raven_mcp/servers/ are running as separate processes.
    """

    def __init__(self, registry) -> None:
        self.registry = registry
        self.tool_to_server = {t.name: t.server for t in ALL_TOOLS}

    async def call(self, tool_name: str, **params) -> ToolResult:
        """Invoke a tool via MCP protocol to an external server."""
        server_name = self.tool_to_server.get(tool_name)
        if not server_name:
            return ToolResult(tool_name=tool_name, success=False, data=None, error=f"Unknown tool: {tool_name}")

        session = self.registry.get_session(server_name)
        if not session:
            return ToolResult(tool_name=tool_name, success=False, data=None, error=f"Server not running: {server_name}")

        try:
            result = await session.call_tool(tool_name, arguments=params)
            content_text = result.content[0].text if result.content else "{}"
            try:
                data = json.loads(content_text)
            except Exception:
                data = content_text
            return ToolResult(tool_name=tool_name, success=True, data=data)
        except Exception as e:
            return ToolResult(tool_name=tool_name, success=False, data=None, error=str(e))
