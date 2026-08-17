"""
tools/tool_registry.py
----------------------
Registry mapping available internal and external tools.
"""

from __future__ import annotations

from typing import Dict, List
from tools.external.sqlmap_runner import SqlmapRunner
from tools.external.ffuf_runner import FfufRunner
from tools.external.nuclei_runner import NucleiRunner


class ToolRegistry:
    """Provides lookup and status for pentest tools."""

    @staticmethod
    def get_tool_status() -> Dict[str, bool]:
        return {
            "http_prober": True,
            "dir_fuzzer": True,
            "auth_tester": True,
            "secret_scanner": True,
            "port_scanner": True,
            "dep_auditor": True,
            "sqlmap": SqlmapRunner.is_available(),
            "ffuf": FfufRunner.is_available(),
            "nuclei": NucleiRunner.is_available()
        }
