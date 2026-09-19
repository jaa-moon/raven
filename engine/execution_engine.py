"""
engine/execution_engine.py
--------------------------
Safe execution engine for Raven assessment agents.

Coordinates concurrent and sequential agent execution, enforces scope
and budget limits per action, and isolates agent exceptions.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from engine.assessment_context import AssessmentContext
from engine.recovery_controller import FailureType, RecoveryAction, RecoveryController
from engine_models.capabilities import CapabilityManifest

logger = logging.getLogger("raven.engine.execution")


class ExecutionEngine:
    """
    Coordinates safe, isolated execution of specialized security assessment agents.
    """

    def __init__(
        self,
        context: AssessmentContext,
        recovery_controller: Optional[RecoveryController] = None,
    ) -> None:
        self.context = context
        self.recovery = recovery_controller or RecoveryController()

    async def execute_agents_safely(
        self,
        activated_capabilities: List[CapabilityManifest],
        agent_instances: Dict[str, Any],
        parallel_groups: Optional[List[List[str]]] = None,
    ) -> None:
        """
        Run activated agents respecting parallel groups or sequential order.
        """
        state = self.context.state
        budget = self.context.budget_manager

        # If explicit parallel groups are defined by planner, execute group by group
        if parallel_groups:
            for group in parallel_groups:
                if budget.is_exhausted():
                    logger.warning("Assessment budget exhausted before executing next parallel group.")
                    break

                tasks = []
                for cap_id in group:
                    agent = agent_instances.get(cap_id)
                    if agent:
                        tasks.append(self._run_single_agent(cap_id, agent))

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Sequential execution in priority order
            for cap in activated_capabilities:
                if budget.is_exhausted():
                    logger.warning("Assessment budget exhausted. Halting further agent execution.")
                    break

                cap_id = cap.capability_id
                agent = agent_instances.get(cap_id)
                if agent:
                    await self._run_single_agent(cap_id, agent)

    async def _run_single_agent(self, capability_id: str, agent: Any) -> None:
        """Execute a single agent with exception shielding and state syncing."""
        logger.info(f"Starting agent execution for capability: '{capability_id}'")
        try:
            # Check if agent implements async run() or execute()
            if hasattr(agent, "execute"):
                if asyncio.iscoroutinefunction(agent.execute):
                    await agent.execute(self.context)
                else:
                    agent.execute(self.context)
            elif hasattr(agent, "run"):
                if asyncio.iscoroutinefunction(agent.run):
                    await agent.run(self.context)
                else:
                    agent.run(self.context)
            else:
                logger.warning(f"Agent for '{capability_id}' does not implement execute() or run().")

            # Checkpoint state after agent completion
            self.context.budget_manager.sync_to_state(self.context.state)
            self.context.asset_graph.sync_to_state(self.context.state)
            self.context.state.save()
            logger.info(f"Agent for '{capability_id}' completed successfully.")

        except Exception as e:
            logger.error(f"Agent for '{capability_id}' failed: {e}", exc_info=True)
            self.context.state.limitations.append(f"Agent '{capability_id}' encountered an unhandled error: {e}")
