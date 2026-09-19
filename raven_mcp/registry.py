"""
raven_mcp/registry.py
---------------------
Tool registry for Raven MCP layer.

Contains:
- ToolRegistry: In-process registry that dynamically imports tool modules
  from ALL_TOOLS for direct agent-to-tool dispatch (used by InternalGateway).
- MCPRegistry: Subprocess-based MCP server lifecycle manager for external
  MCP client connections (existing, unchanged).
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import Any, Dict, List
from contextlib import AsyncExitStack

from raven_mcp.tool_schema import ALL_TOOLS, ToolSchema


# ── Exceptions ───────────────────────────────────────────────────────────────

class ToolNotFoundError(Exception):
    """Raised when a requested tool name is not in the registry."""
    pass


# ── In-process tool registry ─────────────────────────────────────────────────

class RegisteredTool:
    """A tool resolved from ALL_TOOLS with its imported module and function name."""

    __slots__ = ("schema", "module", "function_name")

    def __init__(self, schema: ToolSchema, module: Any, function_name: str) -> None:
        self.schema = schema
        self.module = module
        self.function_name = function_name

    def get_callable(self):
        """Return the actual callable function from the imported module."""
        return getattr(self.module, self.function_name)


class ToolRegistry:
    """
    Builds the tool registry from ALL_TOOLS at startup.
    Maps tool_name → RegisteredTool so the InternalGateway can
    resolve and call any tool by name without subprocess IPC.
    """

    def __init__(self) -> None:
        self._registry: Dict[str, RegisteredTool] = {}
        self._build()

    def _build(self) -> None:
        for schema in ALL_TOOLS:
            if not schema.module or not schema.function:
                continue  # Skip schemas without in-process mapping
            try:
                mod = importlib.import_module(schema.module)
                self._registry[schema.name] = RegisteredTool(
                    schema=schema,
                    module=mod,
                    function_name=schema.function,
                )
            except ImportError as exc:
                # Log but don't crash — tool will be unavailable
                import logging
                logging.getLogger(__name__).warning(
                    "Failed to import tool module %s for tool %s: %s",
                    schema.module, schema.name, exc,
                )

        # Aliases for seamless universal v3 naming
        aliases = {
            "send_http_request": "http_probe",
            "scan_ports": "port_scan",
            "crawl_endpoints": "dir_fuzz",
        }
        for alias, target_tool in aliases.items():
            if target_tool in self._registry and alias not in self._registry:
                self._registry[alias] = self._registry[target_tool]

    def get(self, tool_name: str) -> RegisteredTool:
        """Resolve a registered tool by name. Raises ToolNotFoundError if missing."""
        if tool_name not in self._registry:
            raise ToolNotFoundError(f"Tool '{tool_name}' not registered")
        return self._registry[tool_name]

    def list_by_group(self, group: str) -> List[ToolSchema]:
        """Return all tool schemas belonging to a server group."""
        return [t.schema for t in self._registry.values()
                if t.schema.server_group == group]

    def all_schemas(self) -> List[ToolSchema]:
        """Return all registered tool schemas."""
        return [t.schema for t in self._registry.values()]

    def all_names(self) -> List[str]:
        """Return all registered tool names."""
        return list(self._registry.keys())


# ── External MCP server registry (existing, unchanged) ───────────────────────

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False


class MCPRegistry:
    """
    Manages the lifecycle of MCP server subprocesses.
    """
    def __init__(self, base_url: str, target_path: str, dependencies: list[str]):
        self.base_url = base_url
        self.target_path = target_path
        self.dependencies = ",".join(dependencies)
        self.sessions: Dict[str, ClientSession] = {}
        self.exit_stack = AsyncExitStack()

    async def start_all(self) -> None:
        """Start all registered MCP servers."""
        server_names = ["network_server", "exploit_server", "auth_server", "secrets_server", "recon_server"]
        for name in server_names:
            await self.start_server(name)

    async def start_server(self, name: str) -> None:
        """Start a specific MCP server and initialize its session."""
        script_path = os.path.join(os.path.dirname(__file__), "servers", f"{name}.py")
        env = os.environ.copy()
        env["RAVEN_BASE_URL"] = self.base_url
        env["RAVEN_TARGET_PATH"] = self.target_path
        env["RAVEN_DEPENDENCIES"] = self.dependencies

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[script_path],
            env=env
        )
        
        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        read_stream, write_stream = stdio_transport
        session = await self.exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
        await session.initialize()
        self.sessions[name] = session

    async def stop_all(self) -> None:
        """Terminate all MCP servers."""
        await self.exit_stack.aclose()
        self.sessions.clear()

    def get_session(self, name: str) -> ClientSession | None:
        """Get the ClientSession for a given server name."""
        return self.sessions.get(name)

    def is_running(self, name: str) -> bool:
        """Check if a server is running."""
        return name in self.sessions
