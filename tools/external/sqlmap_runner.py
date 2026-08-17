"""
tools/external/sqlmap_runner.py
-------------------------------
Optional external wrapper for sqlmap binary.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict


class SqlmapRunner:
    """Runs sqlmap if installed on system PATH."""

    @staticmethod
    def is_available() -> bool:
        return shutil.which("sqlmap") is not None

    def run(self, target_url: str) -> Dict[str, Any]:
        if not self.is_available():
            return {"available": False, "vulnerable": False}

        cmd = ["sqlmap", "-u", target_url, "--batch", "--random-agent", "--level=1"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            vulnerable = "is vulnerable" in res.stdout
            return {
                "available": True,
                "vulnerable": vulnerable,
                "output": res.stdout[:1000]
            }
        except Exception as e:
            return {"available": True, "vulnerable": False, "error": str(e)}
