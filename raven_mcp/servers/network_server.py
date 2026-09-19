import os
import json
import asyncio
from urllib.parse import urlparse

from mcp.server.mcpserver import MCPServer

import httpx
from web.crawler import RavenCrawler
from tools.port_scanner import PortScanner

server = MCPServer("network_server")
base_url = os.environ.get("RAVEN_BASE_URL", "http://127.0.0.1:5000")

@server.tool()
async def crawl_site(depth: int = 3, max_pages: int = 100) -> str:
    """Crawls the target site to discover new endpoints and routes."""
    crawler = RavenCrawler(base_url, depth=depth, max_pages=max_pages)
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, crawler.crawl)
    return f"Crawled {len(res.pages)} pages. Found {len(res.routes)} routes."

@server.tool()
async def port_scan() -> str:
    """Scans common TCP ports on the sandbox host."""
    host = urlparse(base_url).hostname or "127.0.0.1"
    scanner = PortScanner(host=host)
    open_ports = await scanner.scan()
    return f"Open ports: {open_ports}"

@server.tool()
async def http_probe(endpoint: str, method: str = "GET", params: dict | None = None, data: dict | None = None) -> str:
    """Sends a raw HTTP probe to an endpoint."""
    url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        try:
            req = client.build_request(method=method, url=url, params=params, data=data)
            resp = await client.send(req)
            return json.dumps({
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:1000] # truncate
            }, indent=2)
        except Exception as e:
            return f"Error sending probe: {str(e)}"

if __name__ == "__main__":
    asyncio.run(server.run_stdio_async())
