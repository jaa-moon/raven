"""
engine_models/actions.py
------------------------
Structured agent action model for Raven adaptive security assessment.

Every tool invocation must be represented as an AgentAction before execution.
This ensures auditability, scope validation, and hypothesis tracking.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class AgentAction(BaseModel):
    """
    A structured, auditable request from an agent to invoke a tool.

    Every action must declare its purpose, hypothesis, expected observation,
    and impact level. The scope validator and budget manager inspect this
    before allowing execution through the MCP gateway.
    """

    action_id: str = Field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8]}")
    agent_name: str = ""
    capability_id: str = ""

    # Tool execution details
    tool_name: str = ""
    target_asset_id: str = ""
    target: str = ""  # Human-readable target identifier (URL, IP, path, etc.)

    operation_type: str = ""  # e.g., "http_request", "port_scan", "file_analysis"
    method: str = ""  # e.g., "GET", "POST", "TCP_CONNECT"
    parameters: Dict[str, Any] = Field(default_factory=dict)

    # Purpose and hypothesis tracking
    purpose: str = ""  # Why is this action being performed?
    hypothesis: str = ""  # Inline hypothesis statement: "I believe X because Y"
    hypothesis_id: Optional[str] = None
    expected_observation: str = ""  # What would confirm the hypothesis?

    # Impact classification — validated against Scope before execution
    impact_level: Literal[
        "passive",
        "low",
        "moderate",
        "high",
        "destructive",
    ] = "low"

    timeout_seconds: int = 30
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    @property
    def display_summary(self) -> str:
        """Short human-readable summary for logging and dashboard display."""
        return f"[{self.agent_name}] {self.tool_name} → {self.target} ({self.purpose[:60]})"

    def is_valid(self) -> bool:
        """Basic structural validation before scope checking."""
        return bool(self.tool_name and self.purpose and self.target)
