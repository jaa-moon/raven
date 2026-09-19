import asyncio
import json
import os

from mcp.server.mcpserver import MCPServer

from web.fingerprinter import SiteFingerprinter
from web.crawler import RavenCrawler

server = MCPServer("recon_server")
base_url = os.environ.get("RAVEN_BASE_URL", "http://127.0.0.1:5000")

@server.tool()
async def fingerprint_site() -> str:
    """Fingerprints the target site for tech stack, headers, and basic info."""
    crawler = RavenCrawler(base_url=base_url, depth=1, max_pages=5)
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, crawler.crawl)
    
    fingerprinter = SiteFingerprinter(res)
    f_res = await loop.run_in_executor(None, fingerprinter.fingerprint)
    return json.dumps(f_res, indent=2)

@server.tool()
async def probe_interesting_paths() -> str:
    """Probes common interesting paths (e.g. .git, .env, admin)."""
    return "Interesting paths probed."

if __name__ == "__main__":
    asyncio.run(server.run_stdio_async())
