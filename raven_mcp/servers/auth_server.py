import asyncio
import json
import os

from mcp.server.mcpserver import MCPServer
from tools.auth_tester import AuthTester

server = MCPServer("auth_server")
base_url = os.environ.get("RAVEN_BASE_URL", "http://127.0.0.1:5000")

@server.tool()
async def jwt_attack(endpoint: str, sample_jwt: str) -> str:
    """Attempts JWT signature stripping and 'none' algorithm bypass on an endpoint."""
    tester = AuthTester(base_url)
    res = await tester.test_jwt_none_alg(
        endpoint=endpoint,
        sample_jwt=sample_jwt
    )
    return json.dumps(res, indent=2)

@server.tool()
async def session_test(endpoint: str) -> str:
    """Analyzes session cookie generation and entropy."""
    return "Session test not fully mapped to auth_tester yet."

@server.tool()
async def cookie_audit(endpoint: str) -> str:
    """Audits cookie security flags."""
    return "Cookie audit not fully mapped to auth_tester yet."

if __name__ == "__main__":
    asyncio.run(server.run_stdio_async())
