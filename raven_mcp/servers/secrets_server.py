import asyncio
import json
import os

from mcp.server.mcpserver import MCPServer

from tools.secret_scanner import SecretScanner
from tools.dep_auditor import DepAuditor

server = MCPServer("secrets_server")
target_path = os.environ.get("RAVEN_TARGET_PATH", ".")
dependencies = os.environ.get("RAVEN_DEPENDENCIES", "").split(",")

@server.tool()
async def env_scan() -> str:
    """Scans environment files and configuration files for secrets."""
    scanner = SecretScanner(target_path)
    results = scanner.scan()
    return json.dumps(results, indent=2)

@server.tool()
async def key_detect() -> str:
    """Scans source code for hardcoded API keys and credentials."""
    scanner = SecretScanner(target_path)
    results = scanner.scan()
    return json.dumps(results, indent=2)

@server.tool()
async def dep_audit() -> str:
    """Audits third-party dependencies for known CVEs."""
    deps = [d.strip() for d in dependencies if d.strip()]
    auditor = DepAuditor(deps)
    results = auditor.audit()
    return json.dumps(results, indent=2)

if __name__ == "__main__":
    asyncio.run(server.run_stdio_async())
