"""
engine_models/state.py
----------------------
Persistent assessment state for Raven adaptive security assessment.

AssessmentState is the single source of truth for an assessment's progress.
It is persisted outside the LLM context window and supports pause, resume,
crash recovery, and audit history.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from engine_models.assets import AssetRelationship, DiscoveredAsset
from engine_models.coverage import CoverageItem
from engine_models.findings import Finding
from engine_models.hypotheses import Hypothesis
from engine_models.target import Target


# Default state storage root
_ASSESSMENTS_DIR = Path.home() / ".raven" / "assessments"


class AssessmentState(BaseModel):
    """
    Complete, serializable state of a running or completed assessment.

    This is the central data structure that all engine components read
    and write. It is persisted to disk after meaningful transitions to
    enable pause/resume and crash recovery.
    """

    assessment_id: str = ""
    target: Optional[Target] = None

    # Current lifecycle phase
    phase: Literal[
        "initialization",
        "authorization",
        "reconnaissance",
        "classification",
        "planning",
        "assessment",
        "validation",
        "risk_analysis",
        "reporting",
        "complete",
        "paused",
        "failed",
    ] = "initialization"

    # Target understanding (populated by recon + classification)
    target_profile: Dict[str, Any] = Field(default_factory=dict)

    # Asset graph data
    discovered_assets: List[DiscoveredAsset] = Field(default_factory=list)
    asset_relationships: List[AssetRelationship] = Field(default_factory=list)
    attack_surfaces: List[str] = Field(default_factory=list)
    technology_profile: Dict[str, Any] = Field(default_factory=dict)
    component_profile: Dict[str, Any] = Field(default_factory=dict)

    # Capability tracking
    available_capabilities: List[str] = Field(default_factory=list)
    active_capabilities: List[str] = Field(default_factory=list)
    unavailable_capabilities: List[str] = Field(default_factory=list)
    active_agents: List[str] = Field(default_factory=list)
    agent_plans: Dict[str, Any] = Field(default_factory=dict)

    # Hypothesis and test tracking
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    rejected_hypotheses: List[str] = Field(default_factory=list)
    planned_tests: List[str] = Field(default_factory=list)
    completed_tests: List[str] = Field(default_factory=list)
    skipped_tests: List[str] = Field(default_factory=list)

    # Findings lifecycle
    candidate_findings: List[Finding] = Field(default_factory=list)
    confirmed_findings: List[Finding] = Field(default_factory=list)
    inconclusive_findings: List[Finding] = Field(default_factory=list)
    rejected_findings: List[Finding] = Field(default_factory=list)

    # Tool execution audit trail
    tested_actions: List[Dict[str, Any]] = Field(default_factory=list)
    tool_failures: List[Dict[str, Any]] = Field(default_factory=list)

    # Budget counters
    total_tool_calls: int = 0
    total_requests_made: int = 0
    elapsed_seconds: float = 0.0

    # Coverage and transparency
    coverage: List[CoverageItem] = Field(default_factory=list)
    not_assessed: List[str] = Field(default_factory=list)
    assessment_notes: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    # Timestamps
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    last_saved_at: Optional[str] = None

    # ── Persistence ──────────────────────────────────────────────────────────

    def save(self, base_dir: Path | None = None, storage_dir: Path | None = None) -> Path:
        """
        Persist assessment state to disk as JSON.

        Saves to ~/.raven/assessments/<assessment_id>/state.json by default.
        Authorization credentials are stripped before serialization.

        Returns the path to the saved state file.
        """
        root = base_dir or storage_dir or _ASSESSMENTS_DIR
        state_dir = root / self.assessment_id
        state_dir.mkdir(parents=True, exist_ok=True)
        state_file = state_dir / "state.json"

        self.last_saved_at = datetime.now().isoformat()

        # Serialize — strip sensitive credential data from target.authorization
        data = self.model_dump(mode="json")
        if data.get("target") and data["target"].get("authorization"):
            auth = data["target"]["authorization"]
            auth["credentials"] = {}
            auth["api_keys"] = {}
            auth["certificates"] = {}

        # Atomic write via temporary file
        tmp_file = state_dir / f"state.json.tmp.{datetime.now().timestamp()}"
        tmp_file.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        tmp_file.replace(state_file)
        return state_file

    @classmethod
    def load(
        cls,
        assessment_id: str,
        base_dir: Path | None = None,
        storage_dir: Path | None = None,
    ) -> "AssessmentState":
        """
        Resume an assessment from persisted state.

        Raises FileNotFoundError if the state file does not exist.
        """
        root = base_dir or storage_dir or _ASSESSMENTS_DIR
        state_file = root / assessment_id / "state.json"

        if not state_file.exists():
            raise FileNotFoundError(
                f"Assessment state not found: {state_file}"
            )

        data = json.loads(state_file.read_text(encoding="utf-8"))
        return cls.model_validate(data)

    @classmethod
    def list_assessments(cls, base_dir: Path | None = None) -> List[str]:
        """List all assessment IDs with saved state."""
        root = base_dir or _ASSESSMENTS_DIR
        if not root.exists():
            return []
        return [
            d.name
            for d in root.iterdir()
            if d.is_dir() and (d / "state.json").exists()
        ]

    # ── State Helpers ────────────────────────────────────────────────────────

    def add_asset(self, asset: DiscoveredAsset) -> None:
        """Add a discovered asset, avoiding duplicates by asset_id."""
        existing_ids = {a.asset_id for a in self.discovered_assets}
        if asset.asset_id not in existing_ids:
            self.discovered_assets.append(asset)

    def add_relationship(self, relationship: AssetRelationship) -> None:
        """Add an asset relationship."""
        self.asset_relationships.append(relationship)

    def add_candidate_finding(self, finding: Finding) -> None:
        """Add a candidate finding pending validation."""
        self.candidate_findings.append(finding)

    def promote_finding(self, finding_id: str) -> Optional[Finding]:
        """Move a candidate finding to confirmed."""
        for i, f in enumerate(self.candidate_findings):
            if f.finding_id == finding_id:
                finding = self.candidate_findings.pop(i)
                finding.mark_confirmed()
                self.confirmed_findings.append(finding)
                return finding
        return None

    def reject_finding(self, finding_id: str, reason: str = "") -> Optional[Finding]:
        """Move a candidate finding to rejected."""
        for i, f in enumerate(self.candidate_findings):
            if f.finding_id == finding_id:
                finding = self.candidate_findings.pop(i)
                finding.mark_rejected(reason)
                self.rejected_findings.append(finding)
                return finding
        return None

    def record_action(self, action_dict: Dict[str, Any]) -> None:
        """Record a completed tool action for audit trail."""
        self.tested_actions.append(action_dict)
        self.total_tool_calls += 1

    def record_failure(self, failure_dict: Dict[str, Any]) -> None:
        """Record a tool failure."""
        self.tool_failures.append(failure_dict)

    def add_note(self, note: str) -> None:
        """Add an assessment note (observable during or after the run)."""
        self.assessment_notes.append(f"[{datetime.now().isoformat()}] {note}")

    @property
    def all_findings(self) -> List[Finding]:
        """All findings regardless of status."""
        return (
            self.candidate_findings
            + self.confirmed_findings
            + self.inconclusive_findings
            + self.rejected_findings
        )

    @property
    def is_complete(self) -> bool:
        return self.phase in ("complete", "failed")

    @property
    def is_resumable(self) -> bool:
        return self.phase not in ("complete", "failed", "initialization")
