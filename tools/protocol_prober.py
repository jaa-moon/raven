"""
tools/protocol_prober.py
------------------------
Protocol-specific prober for network services in Raven.

Identifies application layer protocols and versions running on open ports:
Redis, MySQL, PostgreSQL, FTP, SMTP, HTTP/S, Memcached, SSH.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict


class ProtocolProber:
    """Probes specific application protocols on a given host and port."""

    def __init__(self, host: str, port: int, timeout: float = 3.0) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    async def probe(self, protocol: str = "auto") -> Dict[str, Any]:
        """Probe the port with a named protocol, or auto-detect by behavior.

        Auto mode tries every known protocol, well-known-port matches first with the
        full timeout, then the rest with a short timeout, so a service on a
        non-standard port (Redis on 7777) is still identified.
        """
        proto = protocol.lower().strip()
        probes = [
            ("redis", self._probe_redis, (6379, 6380)),
            ("memcached", self._probe_memcached, (11211,)),
            ("mysql", self._probe_mysql, (3306, 3307)),
            ("ftp", self._probe_ftp, (21, 2121)),
            ("smtp", self._probe_smtp, (25, 587, 465)),
        ]
        if proto != "auto":
            probes = [p for p in probes if p[0] == proto]
            hinted = probes
            others: list = []
        else:
            hinted = [p for p in probes if self.port in p[2]]
            others = [p for p in probes if self.port not in p[2]]

        for _, fn, _ports in hinted:
            res = await fn()
            if res.get("detected"):
                return res
        full_timeout = self.timeout
        self.timeout = min(full_timeout, 1.0)
        try:
            for _, fn, _ports in others:
                res = await fn()
                if res.get("detected"):
                    return res
        finally:
            self.timeout = full_timeout

        # Generic banner / HTTP probe fallback
        return await self._probe_generic()

    async def _probe_redis(self) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            text = resp.decode("utf-8", errors="replace").strip()
            if "+PONG" in text:
                return {
                    "protocol": "redis",
                    "detected": True,
                    "auth_required": False,
                    "authenticated": True,
                    "response": text,
                    "risk": "HIGH - Redis exposed without authentication",
                }
            elif "NOAUTH" in text:
                return {
                    "protocol": "redis",
                    "detected": True,
                    "auth_required": True,
                    "authenticated": False,
                    "response": text,
                    "risk": "MEDIUM - Redis requires authentication",
                }
        except Exception:
            pass
        return {"detected": False}

    async def _probe_mysql(self) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            packet = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            if len(packet) > 5 and packet[4] == 10:  # MySQL Protocol 10
                # Extract server version string (null-terminated after byte 5)
                null_pos = packet.find(b"\x00", 5)
                version = packet[5:null_pos].decode("ascii", errors="replace") if null_pos > 5 else "unknown"
                return {
                    "protocol": "mysql",
                    "detected": True,
                    "version": version,
                    "auth_required": True,
                    "authenticated": False,
                    "response": f"MySQL server {version}",
                    "risk": "LOW - MySQL port exposed",
                }
        except Exception:
            pass
        return {"detected": False}

    async def _probe_ftp(self) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            banner = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            text = banner.decode("utf-8", errors="replace").strip()
            if text.startswith("220"):
                return {
                    "protocol": "ftp",
                    "detected": True,
                    "auth_required": True,
                    "authenticated": False,
                    "response": text,
                    "risk": "LOW - FTP service active",
                }
        except Exception:
            pass
        return {"detected": False}

    async def _probe_smtp(self) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            banner = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.write(b"EHLO raven\r\n")
            await writer.drain()
            ehlo_resp = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            text = ehlo_resp.decode("utf-8", errors="replace").strip()
            if banner.decode("utf-8", errors="replace").startswith("220"):
                return {
                    "protocol": "smtp",
                    "detected": True,
                    "auth_required": "AUTH" in text,
                    "authenticated": False,
                    "response": text[:200],
                    "risk": "LOW - SMTP service active",
                }
        except Exception:
            pass
        return {"detected": False}

    async def _probe_memcached(self) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            writer.write(b"version\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            text = resp.decode("utf-8", errors="replace").strip()
            if "VERSION" in text:
                return {
                    "protocol": "memcached",
                    "detected": True,
                    "auth_required": False,
                    "authenticated": True,
                    "response": text,
                    "risk": "HIGH - Memcached exposed without authentication",
                }
        except Exception:
            pass
        return {"detected": False}

    async def _probe_generic(self) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            text = data.decode("utf-8", errors="replace").strip()
            if text.startswith("HTTP/"):
                return {
                    "protocol": "http",
                    "detected": True,
                    "auth_required": "401" in text or "403" in text,
                    "authenticated": False,
                    "response": text[:150],
                    "risk": "INFO - HTTP service detected",
                }
            elif text.startswith("SSH-"):
                return {
                    "protocol": "ssh",
                    "detected": True,
                    "auth_required": True,
                    "authenticated": False,
                    "response": text[:100],
                    "risk": "INFO - SSH service detected",
                }
        except Exception as e:
            return {
                "protocol": "unknown",
                "detected": False,
                "error": str(e),
            }

        return {
            "protocol": "unknown",
            "detected": False,
            "response": "",
        }


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def probe(host: str, port: int, protocol: str = "auto", timeout: float = 3.0) -> Dict[str, Any]:
    """Gateway-callable wrapper for ProtocolProber."""
    prober = ProtocolProber(host=host, port=port, timeout=timeout)
    return await prober.probe(protocol=protocol)
