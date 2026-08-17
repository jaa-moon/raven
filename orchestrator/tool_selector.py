"""
orchestrator/tool_selector.py
-----------------------------
Selects appropriate offensive tools and attack technique blueprints using
RAG stack context and scan depth configuration.
"""

from __future__ import annotations

from typing import Any, Dict, List
from rag.retriever import SecurityRetriever
from reports.models import ProjectProfile


class ToolSelector:
    """
    RAG-guided tool and technique planner.

    Tool selection is dynamic based on:
    - Stack profile (language, framework, dependencies)
    - Scan depth (quick, standard, deep)
    - RAG retrieval results
    """

    def __init__(
        self,
        retriever: SecurityRetriever,
        profile: ProjectProfile,
        depth: str = "standard",
    ) -> None:
        self.retriever = retriever
        self.profile = profile
        self.depth = depth

    def select(self) -> Dict[str, Any]:
        """
        Construct tool selection plans for Agent 1 and Agent 2.
        """
        # Base tools always included
        agent_1_tools = ["http_prober", "dir_fuzzer"]
        agent_2_tools = ["secret_scanner", "auth_tester", "dep_auditor"]

        # Add port scanner for standard and deep scans
        if self.depth in ("standard", "deep"):
            agent_2_tools.append("port_scanner")

        # Deep scans: enable external tools and more aggressive probing
        if self.depth == "deep":
            agent_1_tools.extend(["sqlmap", "nuclei", "ffuf"])

        # Stack-specific tool adjustments
        lang = self.profile.language.lower()
        fw = self.profile.framework.lower()

        if "python" in lang:
            agent_2_tools.append("bandit")
        if "node" in lang or "js" in lang:
            agent_2_tools.append("npm_audit")

        # Incorporate RAG stack technique context
        knowledge_chunks = self.retriever.retrieve_for_stack(self.profile, top_k=5 if self.depth == "deep" else 3)

        return {
            "web_api": agent_1_tools,
            "auth_infra": agent_2_tools,
            "rag_context": knowledge_chunks,
        }
