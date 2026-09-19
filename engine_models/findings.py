"""
engine_models/findings.py
-------------------------
Evidence-backed finding model for Raven adaptive security assessment.

Core design principle: a confirmed finding must never be generated without
reproducible evidence. Inconclusive findings are tracked separately and
must never be presented as confirmed vulnerabilities.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    """Classification of evidence artifacts supporting or refuting a finding."""

    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    CODE_SNIPPET = "code_snippet"
    TOOL_OUTPUT = "tool_output"
    RUNTIME_TRACE = "runtime_trace"
    BINARY_METADATA = "binary_metadata"
    CONFIGURATION = "configuration"
    CLOUD_POLICY = "cloud_policy"
    CONTAINER_METADATA = "container_metadata"
    KUBERNETES_MANIFEST = "kubernetes_manifest"
    DEPENDENCY_RECORD = "dependency_record"
    TIMING_DELTA = "timing_delta"
    DIFF_COMPARISON = "diff_comparison"
    SCREENSHOT = "screenshot"
    LOG_ENTRY = "log_entry"
    REPRODUCTION_STEPS = "reproduction_steps"
    NETWORK_CAPTURE = "network_capture"
    NETWORK_PACKET = "network_packet"
    FILE_CONTENT = "file_content"
    PROCESS_OUTPUT = "process_output"
    BINARY_OUTPUT = "binary_output"
    CONFIG_VALUE = "config_value"
    PACKAGE_MANIFEST = "package_manifest"
    CONFIG_FILE = "config_file"


class ValidationStatus(str, Enum):
    """Validation state of a finding."""

    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"
    PENDING = "pending"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"
    SPA_FALLBACK = "spa_fallback"  # response matched the SPA-fallback baseline
    PROTECTED = "protected"        # resource exists but access is restricted (401/403)


class EvidenceItem(BaseModel):
    """
    A single piece of evidence supporting or refuting a finding.

    Evidence must be concrete, reproducible, and traceable to a specific
    tool execution. Generic observations are not evidence.
    """

    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid.uuid4().hex[:8]}")

    evidence_type: str = "tool_output"  # Uses EvidenceType enum values

    content: str = ""
    raw_data: str = ""
    sanitized_summary: str = ""
    file_path: str = ""
    line_number: Optional[int] = None
    endpoint: str = ""
    confidence: str = "High"
    source_tool: str = ""
    action_id: str = ""  # Links to the AgentAction that produced this evidence
    collected_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class Finding(BaseModel):
    """
    A security finding with evidence-backed validation.

    Findings represent potential or confirmed vulnerabilities discovered
    during assessment. Every finding must carry a validation_status and
    evidence chain. Only confirmed findings with evidence are reportable.
    """

    finding_id: str = Field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:8]}")
    assessment_id: str = ""

    # Classification
    title: str = ""
    vulnerability_type: str = ""
    category: str = ""  # e.g., "injection", "authentication", "configuration"
    cwe_id: str = ""
    cvss_score: float = 0.0

    severity: Literal[
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
    ] = "Medium"

    confidence: Literal[
        "High",
        "Medium",
        "Low",
    ] = "Low"

    validation_status: ValidationStatus = ValidationStatus.PENDING

    # Location and scope
    component_id: Optional[str] = None
    asset_ids: List[str] = Field(default_factory=list)
    location: str = ""  # File path, URL, IP:port, resource ARN, etc.
    target_component: str = ""
    endpoint: str = ""
    asset_description: str = ""  # Description for non-HTTP targets
    affected_resource: str = ""

    # Discovery methodology
    observation: str = ""  # What was observed
    hypothesis: str = ""   # What was hypothesized
    hypothesis_id: Optional[str] = None
    source_agent: str = ""
    test_performed: str = ""  # How it was tested

    # Reproduction
    payload_used: str = ""
    reproduction_steps: List[str] = Field(default_factory=list)
    cli_poc: str = ""  # For non-HTTP targets: netcat, redis-cli, shell PoC
    curl_poc: str = ""  # For web findings: executable curl command

    # Evidence chain
    evidence: List[EvidenceItem] = Field(default_factory=list)

    # Impact and remediation
    technical_impact: str = ""
    business_impact: str = ""
    remediation: str = ""

    # Relationships
    references: List[str] = Field(default_factory=list)  # CWE, CVE, OWASP references
    related_findings: List[str] = Field(default_factory=list)
    attack_path_id: Optional[str] = None

    # Agent provenance
    agent_name: str = ""
    capability_id: str = ""

    # Timestamps
    discovered_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    validated_at: Optional[str] = None

    def is_reportable(self) -> bool:
        """
        A finding is reportable only if it is confirmed, has evidence,
        AND has reproduction instructions (curl_poc, cli_poc, or reproduction_steps).

        This is the core honesty constraint: Raven never presents a finding
        as confirmed without supporting evidence and a reproducible path.
        """
        has_evidence = len(self.evidence) > 0
        has_reproduction = (
            bool(self.curl_poc)
            or bool(self.cli_poc)
            or len(self.reproduction_steps) > 0
            or any(str(e.evidence_type) in ("code_snippet", "file_content", "reproduction_steps") for e in self.evidence)
        )
        return (
            self.validation_status == ValidationStatus.CONFIRMED
            and has_evidence
            and has_reproduction
        )

    def mark_confirmed(self, reason: str = "") -> None:
        """Transition to confirmed status."""
        self.validation_status = ValidationStatus.CONFIRMED
        self.validated_at = datetime.now().isoformat()
        if reason:
            self.test_performed = reason

    def mark_inconclusive(self, reason: str = "") -> None:
        """Transition to inconclusive status."""
        self.validation_status = ValidationStatus.INCONCLUSIVE
        self.validated_at = datetime.now().isoformat()
        if reason:
            self.test_performed = reason

    def mark_rejected(self, reason: str = "") -> None:
        """Transition to rejected status."""
        self.validation_status = ValidationStatus.REJECTED
        self.validated_at = datetime.now().isoformat()
        if reason:
            self.test_performed = reason

    def add_evidence(self, evidence: EvidenceItem) -> None:
        """Append an evidence item to this finding."""
        self.evidence.append(evidence)
