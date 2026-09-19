"""
tools/process_prober.py
-----------------------
Local process inspection tool for Raven adaptive security assessment.

Inspects running processes, open ports/sockets, environment variables,
command-line arguments, and privilege levels.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import psutil


class ProcessProber:
    """Inspects processes running on the local host or container sandbox."""

    SENSITIVE_ENV_KEYS = {
        "password", "secret", "token", "key", "auth", "credential",
        "api_key", "access_token", "private_key", "aws_secret",
    }

    def probe(
        self,
        pid: Optional[int] = None,
        name: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Inspect processes by PID, process name substring, or listening port."""
        results: List[Dict[str, Any]] = []

        if pid is not None:
            proc_data = self._inspect_pid(pid)
            if proc_data:
                results.append(proc_data)
        elif port is not None:
            results = self._inspect_by_port(port)
        elif name:
            results = self._inspect_by_name(name)
        else:
            # Return current process information by default
            proc_data = self._inspect_pid(os.getpid())
            if proc_data:
                results.append(proc_data)

        return {
            "found": len(results) > 0,
            "count": len(results),
            "processes": results,
        }

    def _inspect_pid(self, pid: int) -> Optional[Dict[str, Any]]:
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                cmdline = p.cmdline()
                username = p.username()
                status = p.status()
                exe = p.exe()
                cwd = p.cwd()

                # Get network connections safely
                connections = []
                try:
                    for conn in p.connections(kind="inet"):
                        connections.append({
                            "fd": conn.fd,
                            "family": str(conn.family),
                            "type": str(conn.type),
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                            "status": conn.status,
                        })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Get open files safely
                open_files = []
                try:
                    for f in p.open_files()[:20]:  # Limit to 20
                        open_files.append(f.path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Sanitize environment variables
                env = {}
                try:
                    raw_env = p.environ()
                    for k, v in raw_env.items():
                        if any(s in k.lower() for s in self.SENSITIVE_ENV_KEYS):
                            env[k] = "****** [REDACTED]"
                        else:
                            env[k] = v[:200]  # truncate long values
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                return {
                    "pid": p.pid,
                    "name": p.name(),
                    "exe": exe,
                    "cwd": cwd,
                    "cmdline": " ".join(cmdline),
                    "username": username,
                    "status": status,
                    "connections": connections,
                    "open_files": open_files,
                    "environ_keys": list(env.keys()),
                    "sanitized_environ": env,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _inspect_by_name(self, name_query: str) -> List[Dict[str, Any]]:
        matches = []
        name_lower = name_query.lower()
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if name_lower in p.info["name"].lower():
                    data = self._inspect_pid(p.info["pid"])
                    if data:
                        matches.append(data)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if len(matches) >= 10:
                break
        return matches

    def _inspect_by_port(self, target_port: int) -> List[Dict[str, Any]]:
        matches = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == target_port:
                if conn.pid:
                    data = self._inspect_pid(conn.pid)
                    if data and data not in matches:
                        matches.append(data)
        return matches


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def probe(
    pid: Optional[int] = None,
    name: Optional[str] = None,
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """Gateway-callable wrapper for ProcessProber."""
    prober = ProcessProber()
    return prober.probe(pid=pid, name=name, port=port)
