"""
adapters/tool_adapters/analyzer_adapter.py
------------------------------------------
Normalizes static code, secret scanner, and dependency auditor results.
"""

from typing import Any, Dict
from engine_models.results import NormalizedToolResult


class AnalyzerToolAdapter:
    """Normalizes output from static analyzers, secret scanners, and SCA tools."""

    @staticmethod
    def normalize(tool_name: str, target: str, raw_output: Any) -> NormalizedToolResult:
        res = NormalizedToolResult(tool_name=tool_name, target=target)
        if isinstance(raw_output, dict):
            res.data = raw_output
            res.status = "success"
        elif isinstance(raw_output, list):
            res.data = {"items": raw_output}
            res.status = "success"
        else:
            res.data = {"output": str(raw_output)}
        return res
