"""
tools/banner_grabber.py
-----------------------
Network service banner grabber for Raven adaptive security assessment.

Connects to a TCP port, retrieves the initial service greeting/banner,
and determines if TLS is required or active.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any, Dict


class BannerGrabber:
    """
    Connects to TCP services to extract initial service greeting and version banner.
    """

    def __init__(self, host: str, port: int, timeout: float = 3.0) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    async def grab(self) -> Dict[str, Any]:
        """Connect to host:port and read the banner."""
        # 1. First try plaintext connection
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )

            # Send a generic probe if service doesn't speak first (like HTTP)
            # Give service 0.5s to speak first
            banner_data = b""
            try:
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
            except asyncio.TimeoutError:
                # Service waits for client: send basic probe
                writer.write(b"HELP\r\n\r\n")
                await writer.drain()
                try:
                    banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                except asyncio.TimeoutError:
                    pass

            writer.close()
            await writer.wait_closed()

            if banner_data:
                # Check for TLS alert or binary negotiation
                is_tls = banner_data.startswith(b"\x15\x03") or banner_data.startswith(b"\x16\x03")
                clean_banner = banner_data.decode("utf-8", errors="replace").strip()
                return {
                    "host": self.host,
                    "port": self.port,
                    "banner": clean_banner,
                    "tls_detected": is_tls,
                    "raw_bytes_hex": banner_data[:128].hex(),
                    "success": True,
                    "error": None,
                }
        except Exception as e:
            plain_err = str(e)
        else:
            plain_err = None

        # 2. If plaintext failed or gave TLS indicator, attempt TLS connection
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ssl_ctx),
                timeout=self.timeout,
            )

            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            tls_data = await asyncio.wait_for(reader.read(1024), timeout=1.5)

            writer.close()
            await writer.wait_closed()

            clean_banner = tls_data.decode("utf-8", errors="replace").strip()
            return {
                "host": self.host,
                "port": self.port,
                "banner": clean_banner,
                "tls_detected": True,
                "raw_bytes_hex": tls_data[:128].hex(),
                "success": True,
                "error": None,
            }
        except Exception as e:
            tls_err = str(e)

        return {
            "host": self.host,
            "port": self.port,
            "banner": "",
            "tls_detected": False,
            "raw_bytes_hex": "",
            "success": False,
            "error": plain_err or tls_err or "Connection failed",
        }


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def grab(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """Gateway-callable wrapper for BannerGrabber."""
    grabber = BannerGrabber(host=host, port=port, timeout=timeout)
    return await grabber.grab()
