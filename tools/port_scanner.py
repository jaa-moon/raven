"""
tools/port_scanner.py
---------------------
Internal service port scanner for sandbox network environments.
"""

from __future__ import annotations

import asyncio
import socket
from typing import List, Tuple

_COMMON_PORTS = [21, 22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 9200, 27017]


class PortScanner:
    """
    Scans common TCP ports on the sandbox host/container.
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host

    async def scan(self, ports: List[int] | None = None) -> List[int]:
        """Scan TCP ports concurrently and return list of open ports."""
        target_ports = ports or _COMMON_PORTS
        open_ports: List[int] = []

        tasks = [self._check_port(port) for port in target_ports]
        results = await asyncio.gather(*tasks)

        for port, is_open in results:
            if is_open:
                open_ports.append(port)

        return open_ports

    async def _check_port(self, port: int) -> Tuple[int, bool]:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, port),
                timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except Exception:
            return port, False


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def scan(host: str = "127.0.0.1", ports: list | None = None) -> list:
    """Gateway-callable wrapper for PortScanner.scan()."""
    scanner = PortScanner(host)
    return await scanner.scan(ports)

