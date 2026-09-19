"""
intelligence/context.py
-----------------------
Three knowledge layers, kept apart on purpose:

  long-term      KnowledgeBase        (checklists, cases, lessons)
  assessment     AssessmentState      (everything observed in this run)
  agent context  ContextManager.*     (only what the *current* decision needs)

The ContextManager builds a query from the current situation, retrieves from
long-term knowledge, and hands a small, deliberately selected bundle to the
planner / agent / validator. It never forwards the whole state.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.models import Finding, RAGContext, TestTask
from core.state import AssessmentState
from intelligence.rag import KnowledgeBase

_KINDS = ("checklist", "case", "lesson")


class ContextManager:
    def __init__(self, kb: KnowledgeBase, state: AssessmentState) -> None:
        self.kb = kb
        self.state = state

    # -- retrieval, recorded by reference ---------------------------------------

    def _retrieve(self, query: str, purpose: str, top_k: int = 3) -> RAGContext:
        ctx = self.kb.retrieve(query, purpose=purpose, top_k=top_k, kinds=_KINDS)
        self.state.rag_contexts.append({
            "purpose": purpose, "query": query[:200],
            "sources": [s.source for s in ctx.snippets],
        })
        return ctx

    # -- context builders ---------------------------------------------------------

    def for_planning(self) -> RAGContext:
        p = self.state.profile
        failed = [t.capability for t in self.state.failed_tasks][-3:]
        parts = [p.target_type, *p.surfaces[:6], *p.technologies[:5],
                 "authentication" if p.authentication else "", "api" if p.api else "", *failed]
        return self._retrieve(" ".join(x for x in parts if x), "planning")

    def for_task(self, task: TestTask) -> RAGContext:
        p = self.state.profile
        q = f"{task.title} {task.surface} {task.capability} {' '.join(p.technologies[:4])}"
        return self._retrieve(q, f"task:{task.key}")

    def for_finding(self, finding: Finding) -> RAGContext:
        return self._retrieve(f"{finding.category} {finding.title} validation false positive", "validation")

    def lookup(self, query: str, purpose: str) -> List[str]:
        """Titles of the guidance consulted (recorded on validated findings)."""
        return [f"{s.kind}:{s.title}" for s in self._retrieve(query, purpose, top_k=2).snippets]

    def agent_context(self, task: TestTask) -> Dict[str, Any]:
        """The minimal context bundle for one agent decision."""
        rag = self.for_task(task)
        related = [o for o in self.state.observations if o.surface == task.surface][-5:]
        return {
            "task": {"title": task.title, "capability": task.capability, "surface": task.surface},
            "guidance": [{"title": s.title, "text": s.text[:400]} for s in rag.snippets],
            "observations": [{"kind": o.kind, "summary": o.summary} for o in related],
            "target": {"type": self.state.profile.target_type,
                       "technologies": self.state.profile.technologies},
        }
