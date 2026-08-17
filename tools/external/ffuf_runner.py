"""
tools/external/ffuf_runner.py
-----------------------------
Optional external wrapper for ffuf fast web fuzzer binary.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict


class FfufRunner:
    """Runs ffuf if installed on system PATH."""

    @staticmethod
    def is_available() -> bool:
        return shutil.which("ffuf") is not None

    def run(self, target_url: str, wordlist_path: str) -> Dict[str, Any]:
        if not self.is_available():
            return {"available": False, "results": []}

        cmd = ["ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist_path, "-mc", "200,301,302", "-s"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            return {"available": True, "results": lines}
        except Exception as e:
            return {"available": True, "results": [], "error": str(e)}
