"""
raven_mcp/models.py
-------------------
Tool metadata. Tools declare *capabilities* they provide; the planner and
agents reason about capabilities, never about tool names.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field


class ToolError(Exception):
    """Raised by a tool handler to report a classified failure."""

    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ParamSpec(BaseModel):
    type: str = "string"        # string | int | float | bool | list | dict
    required: bool = False
    description: str = ""
    default: Any = None


class ToolDefinition(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str = ""
    capabilities: List[str] = Field(default_factory=list)
    target_types: List[str] = Field(default_factory=list)     # empty = any
    input_schema: Dict[str, ParamSpec] = Field(default_factory=dict)
    output_schema: Dict[str, str] = Field(default_factory=dict)
    risk_level: str = "passive"                               # passive | low | moderate | high
    requirements: List[str] = Field(default_factory=list)     # "py:httpx", "bin:nmap"
    scope_args: Dict[str, str] = Field(default_factory=dict)  # arg name -> url|host|port|path
    timeout_seconds: float = 30.0
    expensive: bool = False
    handler: Optional[Callable[..., Any]] = Field(default=None, exclude=True)

    def missing_requirements(self) -> List[str]:
        missing: List[str] = []
        for req in self.requirements:
            kind, _, name = req.partition(":")
            if kind == "py" and importlib.util.find_spec(name) is None:
                missing.append(req)
            elif kind == "bin" and shutil.which(name) is None:
                missing.append(req)
            elif kind == "os" and name == "posix" and os.name != "posix":
                missing.append(req)
        return missing

    def summary(self) -> Dict[str, Any]:
        return {
            "name": self.name, "description": self.description,
            "capabilities": self.capabilities, "risk_level": self.risk_level,
            "target_types": self.target_types,
        }


_COERCE = {
    "string": str, "int": int, "float": float,
}


def validate_arguments(tool: ToolDefinition, arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Return (cleaned_arguments, errors). Applies defaults and coerces scalars."""
    errors: List[str] = []
    cleaned: Dict[str, Any] = {}

    unknown = sorted(set(arguments) - set(tool.input_schema))
    if unknown:
        errors.append(f"unknown argument(s): {', '.join(unknown)}")

    for name, spec in tool.input_schema.items():
        if name in arguments and arguments[name] is not None:
            value = arguments[name]
            try:
                if spec.type in _COERCE:
                    value = _COERCE[spec.type](value)
                elif spec.type == "bool":
                    value = value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
                elif spec.type == "list" and not isinstance(value, (list, tuple)):
                    raise TypeError("expected list")
                elif spec.type == "dict" and not isinstance(value, dict):
                    raise TypeError("expected dict")
            except (TypeError, ValueError):
                errors.append(f"argument '{name}' must be {spec.type}")
                continue
            cleaned[name] = value
        elif spec.required:
            errors.append(f"missing required argument '{name}'")
        elif spec.default is not None:
            cleaned[name] = spec.default
    return cleaned, errors
