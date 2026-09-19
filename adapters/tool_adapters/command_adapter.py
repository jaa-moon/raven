"""
adapters/tool_adapters/command_adapter.py
-----------------------------------------
Normalizes raw shell command and process execution results.
"""

from typing import Any, Dict
from engine_models.results import NormalizedToolResult


class CommandToolAdapter:
    """Normalizes output from subprocess execution and shell commands."""

    @staticmethod
    def normalize(tool_name: str, target: str, returncode: int, stdout: str, stderr: str) -> NormalizedToolResult:
        res = NormalizedToolResult(tool_name=tool_name, target=target)
        res.data = {"returncode": returncode, "stdout": stdout, "stderr": stderr}
        res.status = "success" if returncode == 0 else "error"
        if stderr and returncode != 0:
            res.errors.append(stderr[:200])
        return res
