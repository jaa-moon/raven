"""
End-to-end binary-target assessments through the real pipeline (intake ->
analysis -> plan -> BinaryAssessmentAgent -> gateway -> validation ->
coverage -> report), against local synthetic fixtures.

New file (not an edit to test_assessments.py) so it stays independent of
concurrent, unrelated work in this directory.
"""

from core.models import CoverageStatus, FindingStatus
from reporting.generator import render_markdown
from tests.fixtures_binary import build_elf64, build_pe

FAST = dict(authorized=True, learn_lessons=False)


# ── ELF: fully supported facets -> ASSESSED ─────────────────────────────────────

async def test_elf_binary_target_is_classified_and_fully_assessed(tmp_path):
    from core.assessment import run_assessment
    binpath = tmp_path / "app.elf"
    binpath.write_bytes(build_elf64(nx_disabled=False, relro="full", pie=True,
                                    needed=["libc.so.6", "libssl.so.3"]))
    state = await run_assessment(str(binpath), **FAST)

    assert state.profile.target_type == "binary"
    assert state.profile.attributes["binary_format"] == "ELF"
    assert state.profile.attributes["binary_arch"] == "x86-64"
    assert state.profile.attributes["binary_imports"] == ["libc.so.6", "libssl.so.3"]

    ran_agents = {t.agent for t in state.tasks}
    assert "binary_assessment" in ran_agents
    assert all(t.status == "done" for t in state.tasks if t.agent == "binary_assessment")

    cov = {c.surface: c for c in state.coverage}
    assert cov["Binary analysis"].status == CoverageStatus.ASSESSED
    # Dynamic/execution-based analysis is a distinct, unimplemented surface: it must
    # be honestly NOT_ASSESSED, never silently rendered as clean or as ASSESSED.
    assert cov["Process & CLI"].status == CoverageStatus.NOT_ASSESSED
    assert "no test was planned" in cov["Process & CLI"].detail.lower()

    md = render_markdown(state)
    assert "Binary analysis" in md and "Process & CLI" in md
    assert "clean" not in md.lower()


async def test_elf_binary_with_missing_hardening_is_confirmed_via_independent_validation(tmp_path):
    from core.assessment import run_assessment
    binpath = tmp_path / "weak.elf"
    binpath.write_bytes(build_elf64(nx_disabled=True, relro="none", pie=False))
    state = await run_assessment(str(binpath), **FAST)

    gaps = [f for f in state.findings if f.category == "BinaryHardeningGap"]
    assert gaps, "expected at least one hardening-gap candidate to have been raised"
    by_prop = {f.signal["property"]: f for f in gaps}
    assert {"nx_stack", "relro", "pie"} <= set(by_prop)
    for prop, f in by_prop.items():
        assert f.status == FindingStatus.CONFIRMED, f"{prop} should have been independently confirmed"
        assert f.validator == "binary_hardening_missing"
        assert f.evidence, "a confirmed finding must carry evidence"

    cov = {c.surface: c for c in state.coverage}
    assert cov["Binary analysis"].status == CoverageStatus.ASSESSED

    md = render_markdown(state)
    assert "BinaryHardeningGap" in md or "Missing" in md
    assert "clean" not in md.lower()


async def test_elf_suspicious_string_is_raised_and_confirmed(tmp_path):
    from core.assessment import run_assessment
    binpath = tmp_path / "leaky.elf"
    binpath.write_bytes(build_elf64(extra_strings=[b"AKIAABCDEFGHIJKLMNOP", b"padding text only"]))
    state = await run_assessment(str(binpath), **FAST)

    hits = [f for f in state.findings if f.category == "SuspiciousEmbeddedString"
            and f.signal.get("type") == "AWS Access Key"]
    assert hits
    assert hits[0].status == FindingStatus.CONFIRMED
    assert hits[0].validator == "binary_suspicious_string"
    assert "AKIAABCDEFGHIJKLMNOP" not in state.model_dump_json()   # never a raw secret in state


# ── PE: import-table parsing deliberately unsupported -> PARTIALLY_ASSESSED ────

async def test_pe_binary_target_is_partially_assessed_because_imports_are_unsupported(tmp_path):
    from core.assessment import run_assessment
    binpath = tmp_path / "app.exe"
    binpath.write_bytes(build_pe(aslr=True, dep=True))
    state = await run_assessment(str(binpath), **FAST)

    assert state.profile.target_type == "binary"
    assert state.profile.attributes["binary_format"] == "PE"

    imports_task = next(t for t in state.tasks if t.agent == "binary_assessment"
                        and t.capability == "binary_imports")
    assert imports_task.status == "blocked"

    cov = {c.surface: c for c in state.coverage}
    assert cov["Binary analysis"].status == CoverageStatus.PARTIALLY_ASSESSED
    assert any("PE import-table" in l or "not implemented" in l for l in state.limitations)

    md = render_markdown(state)
    assert "PARTIALLY_ASSESSED" in md
    assert "clean" not in md.lower()


async def test_pe_binary_with_missing_hardening_is_confirmed(tmp_path):
    from core.assessment import run_assessment
    binpath = tmp_path / "unhardened.exe"
    binpath.write_bytes(build_pe(aslr=False, dep=False))
    state = await run_assessment(str(binpath), **FAST)

    gaps = {f.signal["property"]: f for f in state.findings if f.category == "BinaryHardeningGap"}
    assert {"aslr", "dep"} <= set(gaps)
    for f in gaps.values():
        assert f.status == FindingStatus.CONFIRMED
