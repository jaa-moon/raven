"""
intelligence/lessons.py
-----------------------
Validated learning. Only conclusions that were *independently verified* by
the validator (with evidence) can become lessons; raw tool output, LLM
statements and unvalidated candidates never reach long-term knowledge.
"""

from __future__ import annotations

from typing import List

from core.models import SEVERITY_RANK, Confidence, Finding, FindingStatus, Lesson
from core.state import AssessmentState
from intelligence.rag import KnowledgeBase

MIN_CONFIDENCE = {Confidence.HIGH, Confidence.MEDIUM}


def _context(state: AssessmentState) -> str:
    p = state.profile
    tags = ["SPA"] if p.attributes.get("spa") else []
    return " + ".join([*tags, *p.technologies[:2]]) or p.target_type


def extract_lessons(state: AssessmentState) -> List[Lesson]:
    lessons: List[Lesson] = []
    ctx = _context(state)
    for f in state.findings:
        if not f.evidence or f.validator in ("", "none"):
            continue
        if f.status == FindingStatus.REJECTED and _spa_rejection(f):
            lessons.append(Lesson(
                context=ctx, tags=["spa", "false-positive", "baseline"],
                observation=("Candidate sensitive path returned HTTP 200 but matched the response "
                             "for a nonexistent route."),
                lesson="HTTP 200 alone does not establish route or file existence on this kind of target.",
                recommended_validation=("Compare against a nonexistent-route baseline and check content "
                                        "signatures before reporting."),
                confidence=Confidence.HIGH, source_assessment=state.assessment_id))
        elif f.status == FindingStatus.REJECTED and f.validator == "secret_in_file" and _note_has(f, "placeholder"):
            lessons.append(Lesson(
                context="source repositories", tags=["secrets", "false-positive", "placeholder"],
                observation="Secret patterns matched placeholder values or environment references.",
                lesson="A matched secret pattern is not a leaked credential.",
                recommended_validation="Re-read the line; reject placeholders/env lookups; downgrade test files.",
                confidence=Confidence.HIGH, source_assessment=state.assessment_id))
        elif (f.status == FindingStatus.CONFIRMED and f.confidence == Confidence.HIGH and f.surface
              and SEVERITY_RANK[f.severity.value] >= SEVERITY_RANK["medium"]):
            lessons.append(Lesson(
                kind="case", context=ctx, tags=[f.surface.lower().replace(" ", "-"), f.category.lower()],
                observation=f"Target profile: {ctx}. Surface: {f.surface}. Confirmed: {f.category}.",
                lesson=f"Investigating '{f.surface}' on {ctx} targets yielded a validated {f.category} finding.",
                recommended_validation=f"Re-observe independently ({f.validator}) before reporting.",
                confidence=Confidence.HIGH, source_assessment=state.assessment_id))
    return lessons


def _note_has(f: Finding, word: str) -> bool:
    return any(word in n.lower() for n in f.validation_notes)


def _spa_rejection(f: Finding) -> bool:
    return any(e.kind == "baseline_comparison" and e.data.get("classification") == "spa_fallback"
               for e in f.evidence)


def learn(state: AssessmentState, kb: KnowledgeBase) -> List[str]:
    stored = []
    for lesson in extract_lessons(state):
        if kb.add_lesson(lesson):
            stored.append(lesson.lesson_id)
    state.lessons_learned.extend(stored)
    return stored
