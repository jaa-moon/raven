"""
adapters/tool_adapters/scanner_adapter.py
-----------------------------------------
Normalizes network and web vulnerability scanner results into ToolResult.
"""

from typing import Any, Dict
from engine_models.results import NormalizedToolResult


class ScannerToolAdapter:
    """Normalizes output from port scanners, HTTP probers, and web fuzzers."""

    @staticmethod
    def normalize(tool_name: str, target: str, raw_output: Any) -> NormalizedToolResult:
        res = NormalizedToolResult(tool_name=tool_name, target=target)
        if isinstance(raw_output, dict):
            res.data = raw_output
            res.status = "success" if raw_output.get("status") != "error" else "error"
        else:
            res.data = {"output": str(raw_output)}
        return res
