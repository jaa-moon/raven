"""
core/state.py
-------------
The one and only assessment state. Everything the runtime knows lives here;
components read and write it, and it is persisted atomically so an
interrupted assessment can be resumed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError

from core.models import (
    AgentActivity, CoverageItem, Finding, FindingStatus, InjectionHypothesis, Observation,
    RecoveryRecord, TestPlan, TestTask, ToolCallRecord, new_id, now_iso,
)
from core.profile import TargetProfile
from core.scope import Scope
from core.target import TargetInput


class StateLoadError(Exception):
    """Raised when a saved assessment's state.json exists but cannot be loaded: it is not
    valid JSON, or its content does not match the current AssessmentState schema. Distinct
    from FileNotFoundError, which means no state.json exists at all for that assessment_id."""


def default_state_root() -> Path:
    return Path(os.environ.get("RAVEN_HOME", str(Path.home() / ".raven"))) / "assessments"


class AssessmentState(BaseModel):
    assessment_id: str = Field(default_factory=lambda: new_id("ASM"))
    phase: str = "intake"
    target: Optional[TargetInput] = None
    profile: TargetProfile = Field(default_factory=TargetProfile)
    scope: Scope = Field(default_factory=Scope)

    plan: TestPlan = Field(default_factory=TestPlan)
    tasks: List[TestTask] = Field(default_factory=list)

    observations: List[Observation] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    injection_hypotheses: List[InjectionHypothesis] = Field(default_factory=list)

    tool_calls: List[ToolCallRecord] = Field(default_factory=list)
    recovery_actions: List[RecoveryRecord] = Field(default_factory=list)
    agent_activity: List[AgentActivity] = Field(default_factory=list)

    budget: Dict[str, Any] = Field(default_factory=dict)
    coverage: List[CoverageItem] = Field(default_factory=list)
    overall_state: str = "INCOMPLETE"
    limitations: List[str] = Field(default_factory=list)
    rag_contexts: List[Dict[str, Any]] = Field(default_factory=list)   # references only
    lessons_learned: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

    started_at: str = Field(default_factory=now_iso)
    finished_at: Optional[str] = None
    last_saved_at: Optional[str] = None

    # -- task views ---------------------------------------------------------------

    @property
    def pending_tasks(self) -> List[TestTask]:
        return [t for t in self.tasks if t.status == "pending"]

    @property
    def completed_tasks(self) -> List[TestTask]:
        return [t for t in self.tasks if t.status == "done"]

    @property
    def skipped_tasks(self) -> List[TestTask]:
        return [t for t in self.tasks if t.status in ("skipped", "blocked")]

    @property
    def failed_tasks(self) -> List[TestTask]:
        return [t for t in self.tasks if t.status == "failed"]

    def task_keys(self) -> set:
        return {t.key for t in self.tasks}

    # -- finding views ------------------------------------------------------------

    def findings_by_status(self, status: FindingStatus) -> List[Finding]:
        return [f for f in self.findings if f.status == status]

    @property
    def candidate_findings(self) -> List[Finding]:
        return self.findings_by_status(FindingStatus.CANDIDATE)

    @property
    def confirmed_findings(self) -> List[Finding]:
        return self.findings_by_status(FindingStatus.CONFIRMED)

    @property
    def inconclusive_findings(self) -> List[Finding]:
        return self.findings_by_status(FindingStatus.INCONCLUSIVE)

    @property
    def rejected_findings(self) -> List[Finding]:
        return self.findings_by_status(FindingStatus.REJECTED)

    # -- mutation helpers ---------------------------------------------------------

    def add_limitation(self, text: str) -> None:
        if text and text not in self.limitations:
            self.limitations.append(text)

    def add_note(self, text: str) -> None:
        self.notes.append(f"[{now_iso()}] {text}")

    # -- persistence --------------------------------------------------------------

    def save(self, root: Optional[Path] = None) -> Path:
        base = (root or default_state_root()) / self.assessment_id
        base.mkdir(parents=True, exist_ok=True)
        self.last_saved_at = now_iso()
        target = base / "state.json"
        tmp = base / f"state.json.{os.getpid()}.tmp"
        tmp.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(target)
        return target

    @classmethod
    def load(cls, assessment_id: str, root: Optional[Path] = None) -> "AssessmentState":
        path = (root or default_state_root()) / assessment_id / "state.json"
        if not path.exists():
            raise FileNotFoundError(f"No saved assessment: {assessment_id}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise StateLoadError(f"Saved assessment '{assessment_id}' is corrupt (invalid JSON in "
                                 f"{path}): {e}") from e
        try:
            return cls.model_validate(raw)
        except ValidationError as e:
            raise StateLoadError(f"Saved assessment '{assessment_id}' cannot be loaded — its "
                                 f"state.json does not match the current schema ({path}): {e}") from e

    @classmethod
    def list_ids(cls, root: Optional[Path] = None) -> List[str]:
        base = root or default_state_root()
        if not base.exists():
            return []
        return sorted(d.name for d in base.iterdir() if (d / "state.json").exists())
