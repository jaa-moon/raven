"""
engine/result_processor.py
--------------------------
Result normalization and asset extraction processor for Raven.

Transforms diverse, tool-specific outputs into the standard NormalizedToolResult
contract, and extracts newly discovered assets and evidence.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from engine_models.actions import AgentAction
from engine_models.assets import AssetRelationship, AssetType, DiscoveredAsset
from engine_models.results import NormalizedToolResult

logger = logging.getLogger("raven.engine.result_processor")


class ResultProcessor:
    """
    Normalizes tool outputs and extracts structured observations and new assets.
    """

    def process(
        self,
        action: AgentAction,
        raw_result: Any,
        duration_ms: float = 0.0,
    ) -> NormalizedToolResult:
        """
        Convert any raw tool response into a NormalizedToolResult.
        """
        # 1. Base initialization
        res = NormalizedToolResult(
            action_id=action.action_id,
            tool_name=action.tool_name,
            target=action.target,
            duration_ms=duration_ms,
        )

        # 2. Check if already NormalizedToolResult
        if isinstance(raw_result, NormalizedToolResult):
            return raw_result

        # 3. Handle legacy dataclass ToolResult from gateway.py
        if hasattr(raw_result, "success") and hasattr(raw_result, "data"):
            res.status = "success" if raw_result.success else "error"
            if isinstance(raw_result.data, dict):
                res.data = raw_result.data
            elif isinstance(raw_result.data, str):
                try:
                    res.data = json.loads(raw_result.data)
                except Exception:
                    res.data = {"raw_output": raw_result.data}
            else:
                res.data = {"raw_output": str(raw_result.data)}

            if getattr(raw_result, "error", None):
                res.errors.append(str(raw_result.error))

        # 4. Handle Python dict
        elif isinstance(raw_result, dict):
            res.status = raw_result.get("status", "success")
            res.data = raw_result
            if "error" in raw_result:
                res.errors.append(str(raw_result["error"]))

        # 5. Handle Exception
        elif isinstance(raw_result, Exception):
            res.status = "error"
            res.errors.append(str(raw_result))
            res.data = {"exception": type(raw_result).__name__, "message": str(raw_result)}

        # 6. Handle string output
        elif isinstance(raw_result, str):
            res.status = "success"
            # MCP tool servers (e.g. network_server.http_probe) often return a
            # JSON-encoded string. Parse it so downstream consumers (agents,
            # validators) see structured status_code/headers/body instead of
            # having to re-parse "raw_output" themselves.
            parsed_json: Optional[Dict[str, Any]] = None
            stripped = raw_result.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    candidate = json.loads(stripped)
                    if isinstance(candidate, dict):
                        parsed_json = candidate
                except Exception:
                    parsed_json = None
            if parsed_json is not None:
                res.data = parsed_json
            else:
                res.data = {"raw_output": raw_result}
                if stripped.lower().startswith("error"):
                    res.status = "error"
                    res.errors.append(raw_result)

        # 7. Unpack domain-specific assets and observations
        self._extract_domain_assets(action, res)

        return res

    def _extract_domain_assets(self, action: AgentAction, result: NormalizedToolResult) -> None:
        """Inspect data payload to surface discovered endpoints, ports, or secrets."""
        data = result.data

        # HTTP responses / web crawler
        if action.tool_name in ("send_http_request", "crawl_endpoints"):
            status_code = data.get("status_code") or data.get("status")
            if status_code:
                result.observations.append(f"HTTP {status_code} received from {action.target}")
            headers = data.get("headers", {})
            if "server" in headers:
                result.observations.append(f"Server header identified: {headers['server']}")

            # Discovered endpoints
            endpoints = data.get("discovered_endpoints") or data.get("urls") or []
            for ep in endpoints:
                if isinstance(ep, str):
                    result.discovered_assets.append(
                        {
                            "asset_type": AssetType.ENDPOINT.value,
                            "value": ep,
                            "source": action.tool_name,
                            "confidence": "High",
                        }
                    )

        # Port scanner
        elif action.tool_name in ("scan_ports", "port_scan"):
            open_ports = data.get("open_ports") or data.get("ports") or []
            for p in open_ports:
                port_num = p.get("port") if isinstance(p, dict) else str(p)
                service = p.get("service", "unknown") if isinstance(p, dict) else "unknown"
                result.observations.append(f"Port {port_num} open ({service}) on {action.target}")
                result.discovered_assets.append(
                    {
                        "asset_type": AssetType.PORT.value,
                        "value": str(port_num),
                        "metadata": {"service": service},
                        "source": action.tool_name,
                        "confidence": "High",
                    }
                )

        # Secret scanner
        elif action.tool_name in ("scan_secrets", "secret_scanner"):
            findings = data.get("findings") or data.get("secrets") or []
            for f in findings:
                secret_type = f.get("type", "generic_secret") if isinstance(f, dict) else "secret"
                loc = f.get("file", action.target) if isinstance(f, dict) else action.target
                result.observations.append(f"Potential secret ({secret_type}) in {loc}")
                result.discovered_assets.append(
                    {
                        "asset_type": AssetType.SECRET.value,
                        "value": f"{secret_type} in {loc}",
                        "metadata": f if isinstance(f, dict) else {},
                        "source": action.tool_name,
                        "confidence": "Medium",
                    }
                )

        # Dependency auditor
        elif action.tool_name in ("audit_dependencies", "dep_auditor"):
            cves = data.get("vulnerabilities") or data.get("cves") or []
            for cve in cves:
                pkg = cve.get("package", "unknown") if isinstance(cve, dict) else "unknown"
                cve_id = cve.get("cve_id", "CVE") if isinstance(cve, dict) else "CVE"
                result.observations.append(f"Vulnerable package: {pkg} ({cve_id})")
                result.discovered_assets.append(
                    {
                        "asset_type": AssetType.DEPENDENCY.value,
                        "value": pkg,
                        "metadata": cve if isinstance(cve, dict) else {},
                        "source": action.tool_name,
                        "confidence": "High",
                    }
                )
