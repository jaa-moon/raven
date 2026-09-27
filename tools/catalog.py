"""
tools/catalog.py
----------------
Registers Raven's built-in tools with capability metadata. This is the only
place that knows which concrete function backs which capability.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from raven_mcp.models import ParamSpec as P
from raven_mcp.models import ToolDefinition
from raven_mcp.registry import ToolRegistry

COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3000, 3306, 5000, 5432,
                6379, 8000, 8080, 8443, 9200, 11211, 27017]


# -- adapters: normalize legacy tool outputs into stable dicts --------------------

async def _http_request(**kw: Any) -> Dict[str, Any]:
    from tools.http_client import request
    return await request(**kw)


async def _port_scan(host: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
    from tools.port_scanner import scan
    open_ports = await scan(host=host, ports=ports or COMMON_PORTS)
    return {"host": host, "open_ports": sorted(int(p) for p in open_ports)}


async def _banner_grab(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    from tools.banner_grabber import grab
    return await grab(host, port, timeout)


async def _protocol_probe(host: str, port: int, protocol: str = "auto") -> Dict[str, Any]:
    from tools.protocol_prober import probe
    return await probe(host, port, protocol)


def _mask(value: str) -> str:
    v = re.sub(r"[\"']", "", value.split("=", 1)[-1].split(":", 1)[-1]).strip()
    return (v[:2] + "*" * max(len(v) - 2, 4)) if v else "****"


def _secret_scan(path: str) -> Dict[str, Any]:
    from tools.secret_scanner import scan_secrets
    matches = [
        {"type": m["type"], "file": m["file"], "line": int(m["line"]), "masked": _mask(m["match"])}
        for m in scan_secrets(path)
    ]
    return {"matches": matches}


def _dependency_audit(path: str) -> Dict[str, Any]:
    from tools.dependency_audit import audit_repository
    return audit_repository(path)


def _code_scan(path: str) -> Dict[str, Any]:
    from tools.code_scanner import scan
    return scan(path)


async def _config_scan(path: str) -> Dict[str, Any]:
    from tools.config_scanner import scan
    return await scan(path)


async def _permission_scan(path: str) -> Dict[str, Any]:
    from tools.permission_scanner import scan
    return await scan(path)


def _file_inspect(path: str, start: int = 1, end: int = 0) -> Dict[str, Any]:
    from pathlib import Path
    p = Path(path)
    if not p.is_file():
        return {"exists": False, "lines": []}
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    first = max(int(start), 1)
    last = int(end) if end else min(len(lines), first + 400)
    return {
        "exists": True, "total_lines": len(lines),
        "lines": [{"n": i + 1, "text": lines[i][:400]} for i in range(first - 1, min(last, len(lines)))],
    }


def _repo_inventory(path: str) -> Dict[str, Any]:
    from tools.inventory import repo_inventory
    return repo_inventory(path)


def _file_classify(path: str) -> Dict[str, Any]:
    from tools.inventory import file_classify
    return file_classify(path)


async def _sql_injection_probe(url: str, parameter: str, method: str = "GET", location: str = "query",
                               timeout: float = 10.0) -> Dict[str, Any]:
    from tools.injection_probe import sql_probe
    return await sql_probe(url, parameter, method, location, timeout)


async def _xss_probe(url: str, parameter: str, method: str = "GET", location: str = "query",
                     timeout: float = 10.0) -> Dict[str, Any]:
    from tools.injection_probe import xss_probe
    return await xss_probe(url, parameter, method, location, timeout)


async def _ssrf_probe(url: str, parameter: str, method: str = "GET", location: str = "query",
                      timeout: float = 10.0) -> Dict[str, Any]:
    from tools.injection_probe import ssrf_probe
    return await ssrf_probe(url, parameter, method, location, timeout)


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    net = ["web_application", "network_service", "host"]
    src = ["source_repository"]

    reg.register(ToolDefinition(
        name="http_request", description="Send one HTTP request and return status, headers, body.",
        capabilities=["http_request"], risk_level="passive",
        input_schema={
            "url": P(type="string", required=True), "method": P(type="string", default="GET"),
            "headers": P(type="dict"), "params": P(type="dict"), "data": P(type="dict"),
            "follow_redirects": P(type="bool", default=False), "timeout": P(type="float", default=10.0),
        },
        output_schema={"status_code": "int", "headers": "dict", "body": "str"},
        scope_args={"url": "url"}, requirements=["py:httpx"], handler=_http_request,
    ))
    reg.register(ToolDefinition(
        name="port_scan", description="TCP connect scan of common ports.",
        capabilities=["network_discovery"], target_types=["network_service", "host"], risk_level="low",
        input_schema={"host": P(required=True), "ports": P(type="list")},
        output_schema={"open_ports": "list[int]"}, scope_args={"host": "host"},
        timeout_seconds=45, expensive=True, handler=_port_scan,
    ))
    reg.register(ToolDefinition(
        name="banner_grab", description="Read a service greeting banner from a TCP port.",
        capabilities=["service_identification"], target_types=net, risk_level="passive",
        input_schema={"host": P(required=True), "port": P(type="int", required=True),
                      "timeout": P(type="float", default=3.0)},
        scope_args={"host": "host", "port": "port"}, handler=_banner_grab,
    ))
    reg.register(ToolDefinition(
        name="protocol_probe", description="Identify an application protocol and its auth state.",
        capabilities=["protocol_analysis"], target_types=net, risk_level="low",
        input_schema={"host": P(required=True), "port": P(type="int", required=True),
                      "protocol": P(default="auto")},
        scope_args={"host": "host", "port": "port"}, handler=_protocol_probe,
    ))
    reg.register(ToolDefinition(
        name="secret_scan", description="Find hardcoded credentials in a source tree (values masked).",
        capabilities=["secret_detection"], target_types=src, risk_level="passive",
        input_schema={"path": P(required=True)}, scope_args={"path": "path"}, handler=_secret_scan,
    ))
    reg.register(ToolDefinition(
        name="dependency_audit", description="Check declared dependency versions against known advisories.",
        capabilities=["dependency_audit"], target_types=src, risk_level="passive",
        input_schema={"path": P(required=True)}, scope_args={"path": "path"}, handler=_dependency_audit,
    ))
    reg.register(ToolDefinition(
        name="code_scan", description="Pattern-based static analysis for unsafe constructs.",
        capabilities=["static_code_analysis"], target_types=src, risk_level="passive",
        input_schema={"path": P(required=True)}, scope_args={"path": "path"}, handler=_code_scan,
    ))
    reg.register(ToolDefinition(
        name="config_scan", description="Scan configuration files for insecure settings.",
        capabilities=["config_audit"], target_types=src, risk_level="passive",
        input_schema={"path": P(required=True)}, scope_args={"path": "path"}, handler=_config_scan,
    ))
    reg.register(ToolDefinition(
        name="permission_scan", description="Audit POSIX file permissions.",
        capabilities=["permission_audit"], target_types=src + ["binary"], risk_level="passive",
        input_schema={"path": P(required=True)}, scope_args={"path": "path"},
        requirements=["os:posix"], handler=_permission_scan,
    ))
    reg.register(ToolDefinition(
        name="repo_inventory", description="Inventory a source tree: languages, manifests, configs.",
        capabilities=["repository_inventory"], risk_level="passive",
        input_schema={"path": P(required=True)}, scope_args={"path": "path"}, handler=_repo_inventory,
    ))
    reg.register(ToolDefinition(
        name="file_classify", description="Classify a file (binary format / text) by magic bytes.",
        capabilities=["file_classification"], risk_level="passive",
        input_schema={"path": P(required=True)}, scope_args={"path": "path"}, handler=_file_classify,
    ))
    reg.register(ToolDefinition(
        name="file_inspect", description="Read a line range from a file inside the permitted roots.",
        capabilities=["file_inspection"], target_types=src, risk_level="passive",
        input_schema={"path": P(required=True), "start": P(type="int", default=1), "end": P(type="int", default=0)},
        scope_args={"path": "path"}, handler=_file_inspect,
    ))

    WEB = ["web_application"]
    injection_schema = {
        "url": P(type="string", required=True), "parameter": P(type="string", required=True),
        "method": P(type="string", default="GET"), "location": P(type="string", default="query"),
        "timeout": P(type="float", default=10.0),
    }
    reg.register(ToolDefinition(
        name="sql_injection_probe",
        description="Controlled boolean/error-based SQL injection probe (two benign baselines for jitter + 3 non-destructive payloads).",
        capabilities=["injection.sql.detect", "injection.sql.validate"], target_types=WEB, risk_level="moderate",
        input_schema=injection_schema, scope_args={"url": "url"}, requirements=["py:httpx"],
        timeout_seconds=25.0, expensive=True, handler=_sql_injection_probe,
    ))
    reg.register(ToolDefinition(
        name="xss_probe",
        description="Controlled reflected-XSS probe: one unique-canary payload, context detection, no persistence.",
        capabilities=["injection.xss.reflect", "injection.xss.validate"], target_types=WEB, risk_level="moderate",
        input_schema=injection_schema, scope_args={"url": "url"}, requirements=["py:httpx"],
        timeout_seconds=15.0, handler=_xss_probe,
    ))
    reg.register(ToolDefinition(
        name="ssrf_probe",
        description="Controlled SSRF probe using a Raven-hosted loopback callback canary (never an arbitrary host).",
        capabilities=["injection.ssrf.detect", "injection.ssrf.validate"], target_types=WEB, risk_level="moderate",
        input_schema=injection_schema, scope_args={"url": "url"}, requirements=["py:httpx"],
        timeout_seconds=20.0, expensive=True, handler=_ssrf_probe,
    ))
    return reg
