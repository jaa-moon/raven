"""
core/target.py
--------------
Target intake: parse and normalize what the user typed. This module never
performs security testing; it only classifies the input and (optionally)
checks basic reachability.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel


class InputKind(str, Enum):
    URL = "url"
    IP = "ip"
    HOST = "host"
    DIRECTORY = "directory"
    FILE = "file"


class TargetError(ValueError):
    """Raised when the input cannot be interpreted as a supported target."""


class TargetInput(BaseModel):
    raw_input: str
    input_type: InputKind
    normalized_target: str
    host: Optional[str] = None
    port: Optional[int] = None
    scheme: Optional[str] = None
    path: Optional[str] = None  # filesystem path for directory/file targets


_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


def parse_target(raw: str) -> TargetInput:
    """Classify and normalize *raw* into a TargetInput. Raises TargetError."""
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        raise TargetError("Empty target.")

    # 1. URL
    if re.match(r"^https?://", text, re.I):
        parsed = urlparse(text)
        if not parsed.hostname:
            raise TargetError(f"Invalid URL: {text}")
        scheme = parsed.scheme.lower()
        port = parsed.port or _DEFAULT_PORTS[scheme]
        netloc = parsed.hostname.lower()
        if parsed.port and parsed.port != _DEFAULT_PORTS[scheme]:
            netloc = f"{netloc}:{parsed.port}"
        path = parsed.path.rstrip("/") if parsed.path not in ("", "/") else ""
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return TargetInput(
            raw_input=raw, input_type=InputKind.URL, normalized_target=normalized,
            host=parsed.hostname.lower(), port=port, scheme=scheme,
        )

    # 2. Filesystem path (checked before host so "./project" is never a hostname)
    candidate = Path(text).expanduser()
    if candidate.exists():
        resolved = candidate.resolve()
        kind = InputKind.DIRECTORY if resolved.is_dir() else InputKind.FILE
        return TargetInput(
            raw_input=raw, input_type=kind,
            normalized_target=str(resolved), path=str(resolved),
        )
    if text.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", text):
        raise TargetError(f"Path does not exist: {text}")

    # 2b. A URL-shaped scheme Raven doesn't support (anything but http/https) -- reject with
    # a clear reason here, before it can fall into the bare host:port branch below and produce
    # a misleading "invalid port" error (e.g. "nonexistent://bad-target" splits on its single
    # ':' into host="nonexistent", port="//bad-target").
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", text)
    if scheme_match:
        raise TargetError(
            f"Unsupported URL scheme '{scheme_match.group(1)}' — only http:// and https:// "
            f"are supported: {text}")

    # 3. IP (optionally with :port)
    host_part, port = text, None
    if text.count(":") == 1 and not text.startswith("["):
        host_part, _, port_s = text.partition(":")
        if not port_s.isdigit() or not (0 < int(port_s) < 65536):
            raise TargetError(f"Invalid port in target: {text}")
        port = int(port_s)
    try:
        ip = ipaddress.ip_address(host_part)
        normalized = f"{ip}:{port}" if port else str(ip)
        return TargetInput(
            raw_input=raw, input_type=InputKind.IP, normalized_target=normalized,
            host=str(ip), port=port,
        )
    except ValueError:
        pass

    # 4. Hostname
    if _HOST_RE.match(host_part) and ("." in host_part or host_part.lower() == "localhost"):
        h = host_part.lower()
        return TargetInput(
            raw_input=raw, input_type=InputKind.HOST,
            normalized_target=f"{h}:{port}" if port else h, host=h, port=port,
        )

    raise TargetError(f"Unsupported target: {text!r}")


def check_reachability(target: TargetInput, timeout: float = 3.0) -> bool:
    """Best-effort TCP reachability for network-addressable targets."""
    if target.input_type in (InputKind.DIRECTORY, InputKind.FILE):
        return Path(target.path or "").exists()
    if not target.host:
        return False
    ports = [target.port] if target.port else [80, 443, 22]
    for p in ports:
        try:
            with socket.create_connection((target.host, p), timeout=timeout):
                return True
        except OSError:
            continue
    return False
