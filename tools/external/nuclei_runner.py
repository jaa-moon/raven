"""
tools/external/nuclei_runner.py
--------------------------------
Optional external wrapper for nuclei vulnerability scanner binary.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict


class NucleiRunner:
    """Runs nuclei if installed on system PATH."""

    @staticmethod
    def is_available() -> bool:
        return shutil.which("nuclei") is not None

    def run(self, target_url: str) -> Dict[str, Any]:
        if not self.is_available():
            return {"available": False, "findings": []}

        cmd = ["nuclei", "-u", target_url, "-silent"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            return {"available": True, "findings": lines}
        except Exception as e:
            return {"available": True, "findings": [], "error": str(e)}
