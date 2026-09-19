"""
tools/default_creds_tester.py
-----------------------------
Default credentials auditor for common network services in Raven.

Audits discovered services for unauthenticated access or known factory/dev defaults:
Redis (unauthenticated), FTP (anonymous), HTTP Basic Auth (admin:admin), etc.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any, Dict, List, Optional, Tuple


class DefaultCredsTester:
    """Audits services for weak or default credentials."""

    DEFAULT_PAIRS: Dict[str, List[Tuple[str, str]]] = {
        "http": [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("test", "test"),
            ("guest", "guest"),
        ],
        "ftp": [
            ("anonymous", "anonymous"),
            ("anonymous", "guest@example.com"),
            ("ftp", "ftp"),
            ("admin", "admin"),
        ],
        "redis": [
            ("", ""),  # Redis unauthenticated
            ("default", "redis"),
            ("default", "password"),
        ],
        "postgres": [
            ("postgres", "postgres"),
            ("postgres", ""),
            ("admin", "admin"),
        ],
    }

    def __init__(self, host: str, port: int, service: str = "http", timeout: float = 3.0) -> None:
        self.host = host
        self.port = int(port)
        self.service = service.lower().strip()
        self.timeout = timeout

    async def test(self, custom_pairs: Optional[List[Tuple[str, str]]] = None) -> Dict[str, Any]:
        """Test default credentials against the target service."""
        pairs = custom_pairs or self.DEFAULT_PAIRS.get(self.service, [("admin", "admin"), ("root", "root")])
        successful: List[Dict[str, str]] = []
        tested_count = 0

        for username, password in pairs:
            tested_count += 1
            is_valid = False
            try:
                if self.service in ("http", "https"):
                    is_valid = await self._test_http(username, password)
                elif self.service == "ftp":
                    is_valid = await self._test_ftp(username, password)
                elif self.service == "redis":
                    is_valid = await self._test_redis(password)
                elif self.service == "postgres":
                    is_valid = await self._test_postgres(username, password)
            except Exception:
                is_valid = False

            if is_valid:
                successful.append({
                    "username": username,
                    "password": password,
                    "service": self.service,
                    "notes": "Verified unauthenticated or default credentials",
                })
                # Break early on success to avoid lockout
                break

        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "credentials_tested": tested_count,
            "successful": successful,
            "failed": tested_count - len(successful),
            "vulnerable": len(successful) > 0,
        }

    async def _test_http(self, username: str, password: str) -> bool:
        auth_bytes = f"{username}:{password}".encode("latin1")
        b64_auth = base64.b64encode(auth_bytes).decode("ascii")
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Authorization: Basic {b64_auth}\r\n"
            f"User-Agent: Raven-Security-Audit/3.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout,
        )
        writer.write(req)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
        writer.close()
        await writer.wait_closed()

        first_line = resp.split(b"\r\n")[0].decode("latin1", errors="replace")
        return " 200 " in first_line or " 302 " in first_line or " 301 " in first_line

    async def _test_ftp(self, username: str, password: str) -> bool:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout,
        )
        # Read greeting
        await asyncio.wait_for(reader.read(256), timeout=self.timeout)
        writer.write(f"USER {username}\r\n".encode())
        await writer.drain()
        user_resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)

        # 230: logged in, 331: password required
        if user_resp.startswith(b"230"):
            writer.close()
            await writer.wait_closed()
            return True

        if user_resp.startswith(b"331"):
            writer.write(f"PASS {password}\r\n".encode())
            await writer.drain()
            pass_resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return pass_resp.startswith(b"230")

        writer.close()
        await writer.wait_closed()
        return False

    async def _test_redis(self, password: str) -> bool:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout,
        )
        if password:
            writer.write(f"AUTH {password}\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return b"+OK" in resp
        else:
            writer.write(b"PING\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return b"+PONG" in resp

    async def _test_postgres(self, username: str, password: str) -> bool:
        # Standard PostgreSQL StartupMessage check
        # Length (4 bytes) + Protocol version 3.0 (0x00030000) + user\0<username>\0\0
        body = b"\x00\x03\x00\x00user\x00" + username.encode() + b"\x00\x00"
        msg = (len(body) + 4).to_bytes(4, byteorder="big") + body
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout,
        )
        writer.write(msg)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
        writer.close()
        await writer.wait_closed()
        # Byte 'R' is Authentication response; type 0 = AuthOK (no password required)
        if len(resp) >= 9 and resp[0:1] == b"R":
            auth_type = int.from_bytes(resp[5:9], byteorder="big")
            return auth_type == 0
        return False


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def test_creds(
    host: str,
    port: int,
    service: str = "http",
    custom_creds: Optional[List[Dict[str, str]]] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Gateway-callable wrapper for DefaultCredsTester."""
    pairs = [(c["username"], c["password"]) for c in custom_creds] if custom_creds else None
    tester = DefaultCredsTester(host=host, port=port, service=service, timeout=timeout)
    return await tester.test(custom_pairs=pairs)
