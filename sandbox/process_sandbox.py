"""
sandbox/process_sandbox.py
--------------------------
Manages launching target projects as isolated local processes.

Key design: generates a framework-aware wrapper command that forces the app
to bind to the sandbox's assigned port, regardless of what the app's own
source code says. This is critical because we can't modify the target's code.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional
import httpx
from reports.models import ProjectProfile, SandboxInfo


def _get_free_port() -> int:
    """Find an available local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class ProcessSandbox:
    """
    Spins up the target application as a background child process.

    Critical: The target app's own port configuration is OVERRIDDEN.
    We generate a wrapper command that forces the correct port binding.
    """

    def __init__(self, profile: ProjectProfile) -> None:
        self.profile = profile
        self.process: Optional[subprocess.Popen] = None
        self.temp_dir: Optional[str] = None
        self.port: int = _get_free_port()

    async def launch(self) -> SandboxInfo:
        """Copy project to temp dir, generate wrapper, launch, and health check."""
        target_path = Path(self.profile.path)
        self.temp_dir = tempfile.mkdtemp(prefix="raven_sandbox_")

        # Copy target project files to isolated temp directory
        shutil.copytree(target_path, self.temp_dir, dirs_exist_ok=True)

        # Install target dependencies in the sandbox
        await self._install_deps()

        env = os.environ.copy()
        env["PORT"] = str(self.port)
        env["SERVER_PORT"] = str(self.port)
        env["FLASK_RUN_PORT"] = str(self.port)
        env.update(self.profile.environment)

        cmd = self._build_run_command()

        # Launch process — capture stderr for diagnostics
        self._stderr_path = os.path.join(self.temp_dir, "_raven_stderr.log")
        self._stderr_file = open(self._stderr_path, "w")
        self.process = subprocess.Popen(
            cmd,
            cwd=self.temp_dir,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr_file
        )

        ready = await self._wait_for_health()

        # If launch failed, try to read stderr for diagnosis
        if not ready and self.process and self.process.poll() is not None:
            self._stderr_file.close()
            try:
                err_text = open(self._stderr_path).read()[:500]
                if err_text:
                    print(f"  [Sandbox] Target process stderr:\n{err_text}")
            except Exception:
                pass

        return SandboxInfo(
            mode="process",
            process_pid=self.process.pid if self.process else None,
            host="http://127.0.0.1",
            port=self.port,
            base_url=f"http://127.0.0.1:{self.port}",
            ready=ready
        )

    async def _install_deps(self) -> None:
        """Install target project dependencies in the temp sandbox."""
        if not self.temp_dir:
            return
        temp = Path(self.temp_dir)

        # Python: pip install -r requirements.txt
        req_file = temp / "requirements.txt"
        if req_file.exists():
            try:
                proc = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "pip", "install", "-r", str(req_file),
                    "-q", "--disable-pip-version-check",
                    cwd=self.temp_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                await asyncio.wait_for(proc.wait(), timeout=60)
            except Exception:
                pass

        # Node: npm install
        pkg_file = temp / "package.json"
        if pkg_file.exists():
            try:
                proc = await asyncio.create_subprocess_exec(
                    "npm", "install", "--production",
                    cwd=self.temp_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                await asyncio.wait_for(proc.wait(), timeout=60)
            except Exception:
                pass

    def _build_run_command(self) -> list[str]:
        """
        Generate framework-aware command that FORCES the app to bind to our port.

        This is the critical fix: we can't modify the target's source code,
        so we generate a wrapper that overrides the port at the framework level.
        """
        lang = self.profile.language.lower()
        fw = self.profile.framework.lower()
        entry = self.profile.entry_point or "app.py"
        port = self.port

        if "python" in lang:
            if "flask" in fw:
                # Import the app module and force-run on our port
                module_name = entry.replace(".py", "").replace("/", ".").replace("\\", ".")
                wrapper = (
                    f"import sys; sys.path.insert(0, '.'); "
                    f"import {module_name}; "
                    f"app_obj = getattr({module_name}, 'app', None) or getattr({module_name}, 'application', None); "
                    f"app_obj.run(host='127.0.0.1', port={port}, debug=False, use_reloader=False)"
                )
                return [sys.executable, "-c", wrapper]

            elif "fastapi" in fw:
                module_name = entry.replace(".py", "")
                return [
                    sys.executable, "-m", "uvicorn",
                    f"{module_name}:app",
                    "--host", "127.0.0.1",
                    "--port", str(port),
                    "--log-level", "error"
                ]

            elif "django" in fw:
                return [sys.executable, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"]

            else:
                # Generic Python — try to force PORT env variable
                return [sys.executable, entry]

        if "node" in lang or "js" in lang:
            return ["node", entry]

        if "go" in lang:
            return ["go", "run", entry]

        return [sys.executable, entry]

    async def _wait_for_health(self, timeout: float = 25.0) -> bool:
        """Probe sandbox until the target responds."""
        start_time = time.time()
        base_url = f"http://127.0.0.1:{self.port}"
        health_paths = self.profile.health_check_paths or ["/"]

        async with httpx.AsyncClient(timeout=2.0) as client:
            while time.time() - start_time < timeout:
                if self.process and self.process.poll() is not None:
                    return False
                for path in health_paths:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code < 500:
                            return True
                    except Exception:
                        pass
                await asyncio.sleep(0.8)
        return False

    async def teardown(self) -> None:
        """Terminate child process and clean up temporary directory."""
        # Close stderr file handle to prevent leak
        if hasattr(self, '_stderr_file') and self._stderr_file and not self._stderr_file.closed:
            try:
                self._stderr_file.close()
            except Exception:
                pass

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

        if self.temp_dir and Path(self.temp_dir).exists():
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass
            self.temp_dir = None

