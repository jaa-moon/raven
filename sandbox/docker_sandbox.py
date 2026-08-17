"""
sandbox/docker_sandbox.py
-------------------------
Manages launching target projects in isolated Docker containers.

Uses the docker Python SDK with subprocess fallback for resilient Windows execution.
"""

from __future__ import annotations

import asyncio
import os
import random
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional
import httpx
from reports.models import ProjectProfile, SandboxInfo

_DOCKERFILES_DIR = Path(__file__).parent / "dockerfiles"


def _get_free_port() -> int:
    """Find an available unprivileged local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class DockerSandbox:
    """
    Handles Docker container lifecycle: image templating, building, container execution,
    health checking, and teardown.
    """

    def __init__(self, profile: ProjectProfile) -> None:
        self.profile = profile
        self.container_id: Optional[str] = None
        self.host_port: int = _get_free_port()
        self.image_tag: str = f"raven-target-{random.randint(1000, 9999)}"

    async def launch(self) -> SandboxInfo:
        """Build image, spin up container, and await health check."""
        dockerfile_template = self._select_dockerfile()
        target_dir = Path(self.profile.path)
        runtime_dockerfile = target_dir / ".Dockerfile.raven"

        try:
            # Substitute entry point into Dockerfile template
            content = dockerfile_template.read_text(encoding="utf-8")
            content = content.replace("{entry_point}", self.profile.entry_point or "app.py")
            runtime_dockerfile.write_text(content, encoding="utf-8")

            # Build Docker image
            await self._build_image(target_dir, runtime_dockerfile)

            # Run Docker container
            await self._run_container()

            # Health check loop
            ready = await self._wait_for_health()

            return SandboxInfo(
                mode="docker",
                container_id=self.container_id,
                host="http://127.0.0.1",
                port=self.host_port,
                base_url=f"http://127.0.0.1:{self.host_port}",
                ready=ready
            )

        finally:
            if runtime_dockerfile.exists():
                try:
                    runtime_dockerfile.unlink()
                except Exception:
                    pass

    def _select_dockerfile(self) -> Path:
        lang = self.profile.language.lower()
        if "python" in lang:
            return _DOCKERFILES_DIR / "Dockerfile.python"
        if "node" in lang or "js" in lang or "ts" in lang:
            return _DOCKERFILES_DIR / "Dockerfile.node"
        if "go" in lang:
            return _DOCKERFILES_DIR / "Dockerfile.go"
        if "java" in lang:
            return _DOCKERFILES_DIR / "Dockerfile.java"
        return _DOCKERFILES_DIR / "Dockerfile.python"

    async def _build_image(self, target_dir: Path, dockerfile_path: Path) -> None:
        """Build image using subprocess docker build CLI."""
        cmd = [
            "docker", "build",
            "-t", self.image_tag,
            "-f", str(dockerfile_path),
            str(target_dir)
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        rc = await proc.wait()
        if rc != 0:
            raise RuntimeError(f"Docker build failed with exit code {rc}")

    async def _run_container(self) -> None:
        """Run container with port mapping."""
        target_port = self.profile.detected_port or 5000
        cmd = [
            "docker", "run", "-d", "--rm",
            "-p", f"127.0.0.1:{self.host_port}:{target_port}",
            self.image_tag
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        self.container_id = stdout.decode("utf-8").strip()

    async def _wait_for_health(self, timeout: float = 30.0) -> bool:
        """Probe sandbox base URL until responsive."""
        start_time = time.time()
        base_url = f"http://127.0.0.1:{self.host_port}"
        health_paths = self.profile.health_check_paths or ["/"]

        async with httpx.AsyncClient(timeout=2.0) as client:
            while time.time() - start_time < timeout:
                for path in health_paths:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code < 500:
                            return True
                    except Exception:
                        pass
                await asyncio.sleep(1.0)
        return False

    async def teardown(self) -> None:
        """Stop and remove container and image."""
        if self.container_id:
            cmd = ["docker", "stop", self.container_id]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await proc.wait()
            self.container_id = None

        if self.image_tag:
            cmd = ["docker", "rmi", self.image_tag]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await proc.wait()
