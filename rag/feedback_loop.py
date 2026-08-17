"""
rag/feedback_loop.py
--------------------
Post-scan self-improving loop that updates attack memory and prunes low-yield techniques.
"""

from __future__ import annotations

from typing import List
from rag.memory_store import MemoryStore
from reports.models import FinalReport, ProjectProfile


class FeedbackLoop:
    """
    Ingests final scan reports to refine attack pattern knowledge base over time.
    """

    def __init__(self) -> None:
        self.store = MemoryStore()

    def ingest(self, report: FinalReport) -> None:
        """
        Process scan findings and update attack memory:
        1. Store confirmed findings
        2. Adjust success scores
        """
        all_findings = report.agent_1_findings + report.agent_2_findings

        for finding in all_findings:
            if finding.confirmed:
                self.store.store_successful_pattern(finding, report.project_profile)

    def get_prioritized_techniques(self, profile: ProjectProfile) -> List[str]:
        """
        Retrieve attack techniques for this stack sorted by historical success rate.
        """
        patterns = self.store.get_patterns_for_stack(profile)
        # Sort by success rate descending
        sorted_patterns = sorted(patterns, key=lambda p: p.success_rate, reverse=True)
        return [p.technique for p in sorted_patterns if p.success_rate >= 0.1]
