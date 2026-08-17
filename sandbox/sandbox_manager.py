"""
sandbox/sandbox_manager.py
---------------------------
Unified sandbox coordinator: detects Docker availability and dispatches target execution
to DockerSandbox or ProcessSandbox.
"""

from __future__ import annotations

import subprocess

from reports.models import ProjectProfile, RavenConfig, SandboxInfo
from sandbox.docker_sandbox import DockerSandbox
from sandbox.process_sandbox import ProcessSandbox


def is_docker_available() -> bool:
    """Check if Docker CLI daemon is reachable."""
    try:
        res = subprocess.run(
            ["docker", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        return res.returncode == 0
    except Exception:
        return False


class SandboxManager:
    """
    Manages high-level sandbox lifecycle.
    """

    def __init__(self, profile: ProjectProfile, config: RavenConfig) -> None:
        self.profile = profile
        self.config = config
        self._active_sandbox: DockerSandbox | ProcessSandbox | None = None

    async def launch(self) -> SandboxInfo:
        """Select sandbox engine and launch target project."""
        use_docker = not self.config.no_docker and is_docker_available()

        if use_docker:
            try:
                sandbox = DockerSandbox(self.profile)
                self._active_sandbox = sandbox
                info = await sandbox.launch()
                if info.ready:
                    return info
                # If Docker launched but health check failed, fall back to process
                await sandbox.teardown()
            except Exception:
                pass

        # Process fallback
        sandbox = ProcessSandbox(self.profile)
        self._active_sandbox = sandbox
        return await sandbox.launch()

    async def teardown(self) -> None:
        """Tear down active sandbox environment."""
        if self._active_sandbox:
            await self._active_sandbox.teardown()
            self._active_sandbox = None
