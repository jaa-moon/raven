"""
tests/test_state_persistence.py
-------------------------------
Unit tests for AssessmentState persistence, serialization, and recovery.
"""

import tempfile
from pathlib import Path
from engine.lifecycle_manager import LifecycleManager
from engine_models.findings import EvidenceItem, Finding, ValidationStatus
from engine_models.state import AssessmentState
from engine_models.target import Target, TargetType


def test_assessment_state_save_and_load():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        state = AssessmentState(
            assessment_id="ASM-PERSIST-TEST",
            target=Target(raw_input="https://test.local", target_type=TargetType.WEB_APPLICATION),
            phase="assessment",
        )

        finding = Finding(
            title="Test Inconclusive Finding",
            vulnerability_type="info_leak",
            validation_status=ValidationStatus.INCONCLUSIVE,
            evidence=[EvidenceItem(evidence_type="tool_output", content="sample output")],
        )
        state.inconclusive_findings.append(finding)

        # Save state
        saved_path = state.save(tmp_path / "assessments")
        assert Path(saved_path).exists()

        # Reconstitute state
        loaded = AssessmentState.load("ASM-PERSIST-TEST", storage_dir=tmp_path / "assessments")
        assert loaded.assessment_id == "ASM-PERSIST-TEST"
        assert loaded.phase == "assessment"
        assert len(loaded.inconclusive_findings) == 1
        assert loaded.inconclusive_findings[0].title == "Test Inconclusive Finding"


def test_lifecycle_manager_resumes_paused():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        state = AssessmentState(
            assessment_id="ASM-PAUSED",
            phase="paused",
        )
        state.save(tmp_path / "assessments")

        # Resume via LifecycleManager
        loaded = AssessmentState.load("ASM-PAUSED", storage_dir=tmp_path / "assessments")
        mgr = LifecycleManager(loaded, auto_save=False)
        assert mgr.state.phase == "paused"
        mgr.transition_to("assessment")
        assert mgr.state.phase == "assessment"
