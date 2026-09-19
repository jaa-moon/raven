"""
core/models.py
--------------
Shared contracts for the Raven assessment runtime.

Every component (planner, agents, gateway, validator, reporter) exchanges
these models; nothing passes raw tool output or ad-hoc dicts across a
component boundary.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ── Enums ─────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: Dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class CoverageStatus(str, Enum):
    ASSESSED = "ASSESSED"
    PARTIALLY_ASSESSED = "PARTIALLY_ASSESSED"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"


# ── Evidence / observations / findings ────────────────────────────────────────

class Evidence(BaseModel):
    """A concrete, redacted artifact supporting or refuting a finding."""

    evidence_id: str = Field(default_factory=lambda: new_id("EVD"))
    kind: str = "tool_output"  # http_response | baseline_comparison | file_content | tool_output ...
    summary: str = ""
    data: Dict[str, Any] = Field(default_factory=dict)
    source_tool: str = ""
    created_at: str = Field(default_factory=now_iso)


class Observation(BaseModel):
    """A normalized fact learned from a tool result. Not yet a finding."""

    observation_id: str = Field(default_factory=lambda: new_id("OBS"))
    kind: str = ""  # e.g. http.fingerprint, port.open, file.secret_match
    surface: str = ""
    summary: str = ""
    data: Dict[str, Any] = Field(default_factory=dict)
    source_task: str = ""
    created_at: str = Field(default_factory=now_iso)


class Finding(BaseModel):
    """
    A security finding. Agents only ever create CANDIDATE findings; only the
    validator may move a finding to CONFIRMED / INCONCLUSIVE / REJECTED.
    """

    finding_id: str = Field(default_factory=lambda: new_id("FND"))
    title: str = ""
    category: str = ""
    severity: Severity = Severity.INFO
    status: FindingStatus = FindingStatus.CANDIDATE
    confidence: Confidence = Confidence.NONE

    surface: str = ""
    location: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    reproduction: List[str] = Field(default_factory=list)

    # Machine-readable description of what the agent saw; validators dispatch
    # on signal["validator"] and re-derive the truth from a fresh observation.
    signal: Dict[str, Any] = Field(default_factory=dict)

    evidence: List[Evidence] = Field(default_factory=list)
    validation_notes: List[str] = Field(default_factory=list)
    validator: str = ""
    source_task: str = ""
    created_at: str = Field(default_factory=now_iso)
    validated_at: Optional[str] = None

    @property
    def is_reportable(self) -> bool:
        return self.status == FindingStatus.CONFIRMED and bool(self.evidence)


# ── Tool contracts ────────────────────────────────────────────────────────────

class ToolRequest(BaseModel):
    """An agent's request for a capability, executed via the MCP gateway."""

    request_id: str = Field(default_factory=lambda: new_id("REQ"))
    capability: str = ""
    arguments: Dict[str, Any] = Field(default_factory=dict)
    tool: Optional[str] = None            # explicit tool override (rare)
    exclude_tools: List[str] = Field(default_factory=list)
    purpose: str = ""
    agent: str = ""
    task_id: str = ""


ToolStatus = Literal[
    "ok", "error", "timeout", "out_of_scope", "invalid_args",
    "tool_unavailable", "budget_exhausted", "target_unreachable",
    "rate_limited", "auth_failure",
]


class ToolResult(BaseModel):
    """Normalized result of a gateway execution."""

    request_id: str = ""
    tool: str = ""
    capability: str = ""
    status: ToolStatus = "ok"
    data: Dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    duration_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class ToolCallRecord(BaseModel):
    request_id: str
    tool: str = ""
    capability: str = ""
    agent: str = ""
    task_id: str = ""
    status: str = "ok"
    duration_ms: float = 0.0
    error: str = ""
    purpose: str = ""
    timestamp: str = Field(default_factory=now_iso)


class RecoveryRecord(BaseModel):
    request_id: str = ""
    capability: str = ""
    tool: str = ""
    failure_type: str = ""
    action: str = ""
    detail: str = ""
    timestamp: str = Field(default_factory=now_iso)


# ── Planning ──────────────────────────────────────────────────────────────────

TaskStatus = Literal["pending", "running", "done", "failed", "skipped", "blocked"]


class TestTask(BaseModel):
    """One unit of assessment work: an agent applying a capability to a surface."""

    __test__ = False  # not a pytest class

    task_id: str = Field(default_factory=lambda: new_id("TSK"))
    key: str = ""                # stable dedupe key, e.g. "web.headers::http://x"
    agent: str = ""
    capability: str = ""
    surface: str = ""
    title: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    priority: int = 50           # 0-100, higher = sooner
    cost: int = 1                # rough tool-call cost, used for budget-aware selection
    status: TaskStatus = "pending"
    result_summary: str = ""
    attempts: int = 0


class TestPlan(BaseModel):
    __test__ = False

    plan_id: str = Field(default_factory=lambda: new_id("PLN"))
    version: int = 1
    generated_by: Literal["deterministic", "llm"] = "deterministic"
    rationale: str = ""
    task_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)


class CoverageItem(BaseModel):
    surface: str
    status: CoverageStatus = CoverageStatus.NOT_ASSESSED
    detail: str = ""
    task_ids: List[str] = Field(default_factory=list)


# ── Knowledge / context ───────────────────────────────────────────────────────

class RAGSnippet(BaseModel):
    source: str = ""
    title: str = ""
    kind: Literal["checklist", "case", "lesson", "knowledge"] = "knowledge"
    text: str = ""
    score: float = 0.0


class RAGContext(BaseModel):
    """Result of one contextual retrieval; only a reference is kept in state."""

    query: str = ""
    purpose: str = ""
    snippets: List[RAGSnippet] = Field(default_factory=list)
    created_at: str = Field(default_factory=now_iso)


class AgentActivity(BaseModel):
    agent: str
    task_id: str
    title: str = ""
    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None
    outcome: str = "running"


class Lesson(BaseModel):
    """Validated, reusable knowledge extracted from an assessment."""

    lesson_id: str = Field(default_factory=lambda: new_id("LSN"))
    kind: Literal["lesson", "case"] = "lesson"
    context: str = ""        # e.g. "SPA"
    observation: str = ""
    lesson: str = ""
    recommended_validation: str = ""
    tags: List[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    source_assessment: str = ""
    created_at: str = Field(default_factory=now_iso)
