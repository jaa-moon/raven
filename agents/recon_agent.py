"""
agents/recon_agent.py
---------------------
Universal reconnaissance agent for Raven adaptive security assessments.

Autonomously fingerprints targets, discovers initial assets, enumerates endpoints/ports/files,
and constructs the initial attack surface graph without performing vulnerability exploitation.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine_models.actions import AgentAction
from engine_models.assets import AssetRelationship, AssetType, DiscoveredAsset
from engine_models.target import TargetType

logger = logging.getLogger("raven.agents.recon")


class ReconAgent(BaseSpecializedAgent):
    """
    Universal reconnaissance agent that adapts discovery techniques to target type.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "UniversalReconAgent"
        self.capability_id = "reconnaissance"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        await self.run()

    async def run(self) -> None:
        """Execute discovery workflow based on target type."""
        target = self.context.target
        tt = target.target_type
        logger.info(f"ReconAgent commencing discovery on target type: {tt.value} ({target.raw_input})")

        # 1. Web & API Targets
        if tt in (
            TargetType.WEB_APPLICATION,
            TargetType.REST_API,
            TargetType.GRAPHQL_API,
            TargetType.MOBILE_BACKEND,
        ):
            await self._recon_web(target.raw_input)

        # 2. Repository & Source Code Targets
        elif tt in (
            TargetType.SOURCE_REPOSITORY,
            TargetType.LIBRARY,
            TargetType.LOCAL_APPLICATION,
        ):
            await self._recon_repository(target.raw_input)

        # 3. Network Targets
        elif tt in (TargetType.NETWORK_SERVICE, TargetType.NETWORK_RANGE):
            await self._recon_network(target.raw_input)

        # 4. Container Targets
        elif tt in (TargetType.CONTAINER, TargetType.CONTAINER_IMAGE):
            await self._recon_container(target.raw_input)

        # 5. Native Binary
        elif tt == TargetType.NATIVE_BINARY:
            await self._recon_binary(target.raw_input)

        # 6. Hybrid or Unknown
        else:
            await self._recon_generic(target.raw_input)

        # Sync discovered assets into state
        self.context.asset_graph.sync_to_state(self.context.state)
        logger.info(
            f"ReconAgent completed: {len(self.context.asset_graph.all_assets())} assets discovered."
        )

    async def _recon_web(self, url: str) -> None:
        """Probe web target for technologies, response headers, and endpoints."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Root URL asset
        root_asset = DiscoveredAsset(
            asset_type=AssetType.URL,
            value=base_url,
            source=self.agent_name,
            confidence="High",
            metadata={"scheme": parsed.scheme, "host": parsed.hostname, "port": parsed.port},
        )
        self.context.asset_graph.add_asset(root_asset)

        # Probe root endpoint
        action = AgentAction(
            agent_name=self.agent_name,
            tool_name="send_http_request",
            target=base_url,
            operation_type="http_request",
            method="GET",
            parameters={"url": base_url, "method": "GET"},
            purpose="Fingerprint web server headers and initial response",
            impact_level="passive",
        )

        res = await self.execute_action(action)
        if res.is_success and res.data:
            headers = res.data.get("headers", {})
            status_code = res.data.get("status_code", 200)

            tech_info: Dict[str, Any] = {"status_code": status_code}
            if "server" in headers:
                tech_info["server"] = headers["server"]
            if "x-powered-by" in headers:
                tech_info["x_powered_by"] = headers["x-powered-by"]
            if "content-type" in headers:
                tech_info["content_type"] = headers["content-type"]

            self.context.state.technology_profile.update(tech_info)

            # Probe robots.txt for hidden paths
            robots_url = f"{base_url}/robots.txt"
            robots_action = AgentAction(
                agent_name=self.agent_name,
                tool_name="send_http_request",
                target=robots_url,
                operation_type="http_request",
                method="GET",
                parameters={"url": robots_url, "method": "GET"},
                purpose="Inspect robots.txt for hidden disallowed paths",
                impact_level="passive",
            )
            robots_res = await self.execute_action(robots_action)
            if robots_res.is_success and robots_res.data:
                body = str(robots_res.data.get("body", ""))
                for line in body.splitlines():
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            endpoint = parts[1].strip()
                            if endpoint and endpoint != "/":
                                ep_asset = DiscoveredAsset(
                                    asset_type=AssetType.ENDPOINT,
                                    value=f"{base_url}{endpoint}",
                                    parent_asset_id=root_asset.asset_id,
                                    source="robots.txt",
                                    confidence="High",
                                )
                                self.context.asset_graph.add_asset(ep_asset)

    async def _recon_repository(self, repo_path: str) -> None:
        """Inspect repository filesystem structure and detect framework & dependencies."""
        p = Path(repo_path)
        if not p.exists():
            return

        repo_asset = DiscoveredAsset(
            asset_type=AssetType.REPOSITORY,
            value=str(p.resolve()),
            source=self.agent_name,
            confidence="High",
        )
        self.context.asset_graph.add_asset(repo_asset)

        # Detect tech stack
        detected_tech = []
        dep_files = []

        if (p / "requirements.txt").exists():
            detected_tech.append("Python")
            dep_files.append(str(p / "requirements.txt"))
        if (p / "package.json").exists():
            detected_tech.append("Node.js / JavaScript")
            dep_files.append(str(p / "package.json"))
        if (p / "go.mod").exists():
            detected_tech.append("Go")
            dep_files.append(str(p / "go.mod"))
        if (p / "pom.xml").exists() or (p / "build.gradle").exists():
            detected_tech.append("Java")
        if (p / "Cargo.toml").exists():
            detected_tech.append("Rust")
            dep_files.append(str(p / "Cargo.toml"))
        if (p / "Dockerfile").exists():
            detected_tech.append("Docker")

        self.context.state.technology_profile["languages_frameworks"] = detected_tech

        # Walk first 2 levels to index key files
        file_count = 0
        for root, dirs, files in os.walk(p):
            # Skip hidden and cache dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "venv", "__pycache__")]
            for f in files:
                file_path = Path(root) / f
                rel_path = str(file_path.relative_to(p))
                file_asset = DiscoveredAsset(
                    asset_type=AssetType.FILE,
                    value=rel_path,
                    parent_asset_id=repo_asset.asset_id,
                    source=self.agent_name,
                    confidence="High",
                )
                self.context.asset_graph.add_asset(file_asset)
                file_count += 1
                if file_count >= 100:  # Cap initial recon tree to 100 files
                    break
            if file_count >= 100:
                break
        
        # Secret scan
        action = AgentAction(
            agent_name=self.agent_name,
            tool_name="secret_scan",
            target=repo_path,
            operation_type="secret_scan",
            parameters={"path": repo_path},
            purpose="Scan repository for hardcoded secrets",
            impact_level="passive",
        )
        await self.execute_action(action)

    async def _recon_network(self, host: str) -> None:
        """Scan host for initial open ports, grab banners, and probe protocols."""
        parts = host.split(":")
        clean_host = parts[0]
        explicit_port = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else None

        host_asset = DiscoveredAsset(
            asset_type=AssetType.HOST,
            value=clean_host,
            source=self.agent_name,
            confidence="High",
        )
        self.context.asset_graph.add_asset(host_asset)

        open_ports: List[int] = [explicit_port] if explicit_port else []

        if self.context.is_active_permitted:
            scan_action = AgentAction(
                agent_name=self.agent_name,
                tool_name="port_scan",
                target=clean_host,
                operation_type="port_scan",
                parameters={"host": clean_host, "ports": [explicit_port] if explicit_port else [21, 22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080]},
                purpose="Discover open ports and listening network services",
                impact_level="moderate",
            )
            scan_res = await self.execute_action(scan_action)
            if scan_res.is_success and isinstance(scan_res.data, list):
                open_ports = list(set(open_ports + scan_res.data))

        # For every open port, perform banner grab & protocol probe
        for port in open_ports[:10]:  # Limit to first 10 ports
            # 1. Banner Grab
            bg_action = AgentAction(
                agent_name=self.agent_name,
                tool_name="banner_grab",
                target=f"{clean_host}:{port}",
                operation_type="banner_grab",
                parameters={"host": clean_host, "port": port},
                purpose=f"Grab service banner on port {port}",
                impact_level="passive",
            )
            bg_res = await self.execute_action(bg_action)
            banner = bg_res.data.get("banner", "") if bg_res.is_success else ""

            # 2. Protocol Probe
            proto_action = AgentAction(
                agent_name=self.agent_name,
                tool_name="protocol_probe",
                target=f"{clean_host}:{port}",
                operation_type="protocol_probe",
                parameters={"host": clean_host, "port": port, "protocol": "auto"},
                purpose=f"Probe application protocol on port {port}",
                impact_level="passive",
            )
            proto_res = await self.execute_action(proto_action)
            protocol = proto_res.data.get("protocol", "unknown") if proto_res.is_success else "unknown"

            port_asset = DiscoveredAsset(
                asset_type=AssetType.PORT,
                value=f"{clean_host}:{port}",
                parent_asset_id=host_asset.asset_id,
                source=self.agent_name,
                confidence="High",
                metadata={
                    "port": port,
                    "banner": banner[:100],
                    "protocol": protocol,
                    "auth_required": proto_res.data.get("auth_required") if proto_res.is_success else None,
                },
            )
            self.context.asset_graph.add_asset(port_asset)

        # Environment scan
        env_action = AgentAction(
            agent_name=self.agent_name,
            tool_name="env_scan",
            target=clean_host,
            operation_type="env_scan",
            parameters={"host": clean_host},
            purpose="Scan host for environment leakage",
            impact_level="passive",
        )
        await self.execute_action(env_action)

        # Set target profile recommendations
        self.context.state.target_profile.update({
            "target_type": "network_service",
            "host": clean_host,
            "open_ports": open_ports,
            "recommended_agents": ["network_agent", "auth_identity_agent"] if open_ports else ["network_agent"],
        })

    async def _recon_container(self, target_str: str) -> None:
        """Record container image asset."""
        cont_asset = DiscoveredAsset(
            asset_type=AssetType.CONTAINER_IMAGE,
            value=target_str,
            source=self.agent_name,
            confidence="High",
        )
        self.context.asset_graph.add_asset(cont_asset)
        self.context.state.target_profile.update({
            "target_type": "container_image",
            "recommended_agents": ["configuration_agent", "dependency_agent"],
        })

    async def _recon_binary(self, binary_path: str) -> None:
        """Record native binary asset and inspect local permissions."""
        p = Path(binary_path)
        bin_asset = DiscoveredAsset(
            asset_type=AssetType.BINARY,
            value=str(p.resolve()) if p.exists() else binary_path,
            source=self.agent_name,
            confidence="High",
            metadata={"size_bytes": p.stat().st_size if p.exists() else 0},
        )
        self.context.asset_graph.add_asset(bin_asset)

        # Check process if running
        action = AgentAction(
            agent_name=self.agent_name,
            tool_name="process_probe",
            target=p.name,
            operation_type="process_probe",
            parameters={"name": p.stem},
            purpose="Check if target binary is currently running as a process",
            impact_level="passive",
        )
        await self.execute_action(action)

        self.context.state.target_profile.update({
            "target_type": "native_binary",
            "binary_path": str(p),
            "recommended_agents": ["binary_agent", "configuration_agent"],
        })

    async def _recon_generic(self, target_str: str) -> None:
        """Generic asset recording for novel target inputs."""
        gen_asset = DiscoveredAsset(
            asset_type=AssetType.UNKNOWN,
            value=target_str,
            source=self.agent_name,
            confidence="Low",
        )
        self.context.asset_graph.add_asset(gen_asset)
