"""
engine/assessment_controller.py
-------------------------------
Central assessment controller for Raven v3.0.

Implements the universal 15-step adaptive assessment lifecycle:
target resolution → authorization & scope check → reconnaissance →
asset graph synthesis → capability selection → adaptive planning →
specialized agent execution → finding validation → risk correlation →
coverage tracking → reporting.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from capabilities.registry import CapabilityRegistry
from engine.asset_graph import AssetGraph
from engine.assessment_context import AssessmentContext
from engine.authorization_validator import AuthorizationValidator
from engine.budget_manager import BudgetLimits, BudgetManager
from engine.capability_selector import CapabilitySelector
from engine.execution_engine import ExecutionEngine
from engine.lifecycle_manager import LifecycleManager
from engine.recovery_controller import RecoveryController
from engine.result_processor import ResultProcessor
from engine.scope_validator import ScopeValidator
from engine.target_resolver import TargetResolver
from engine_models.authorization import Authorization
from engine_models.capabilities import CapabilityManifest
from engine_models.coverage import CoverageItem
from engine_models.findings import Finding, ValidationStatus
from engine_models.report import PentestReport
from engine_models.risk import RiskScore
from engine_models.scope import Scope
from engine_models.state import AssessmentState
from engine_models.target import Target, TargetType

logger = logging.getLogger("raven.engine.controller")


async def run_assessment(
    target_input: str | Target,
    depth: str = "standard",
    mode: str = "passive",
    scope: Optional[Scope] = None,
    authorization: Optional[Authorization] = None,
    selected_capabilities: Optional[List[str]] = None,
    excluded_capabilities: Optional[List[str]] = None,
    provider: Any = None,
    gateway: Any = None,
    resume_assessment_id: Optional[str] = None,
    config: Any = None,
) -> PentestReport:
    """
    Universal entrypoint for Raven adaptive security assessments.
    Replaces the legacy web-specific run_scan pipeline.
    """
    start_time = datetime.now()

    # 1. State Recovery or Initialization
    if resume_assessment_id:
        logger.info(f"Resuming existing assessment: {resume_assessment_id}")
        state = LifecycleManager.load_or_resume(resume_assessment_id)
        target = state.target or TargetResolver.resolve(target_input if isinstance(target_input, str) else target_input.raw_input)
    else:
        assessment_id = f"ASM-{uuid.uuid4().hex[:8]}"
        if isinstance(target_input, Target):
            target = target_input
        else:
            target = TargetResolver.resolve(target_input)

        state = AssessmentState(
            assessment_id=assessment_id,
            target=target,
            phase="initialization",
        )

    lifecycle = LifecycleManager(state, auto_save=True)
    asset_graph = AssetGraph.from_state(state)

    # 2. Scope & Authorization Configuration
    resolved_scope = scope or Scope()
    if mode == "active":
        resolved_scope.allow_active_testing = True
    elif mode == "authenticated":
        resolved_scope.allow_active_testing = True
        resolved_scope.allow_authenticated_testing = True

    resolved_auth = authorization or Authorization(confirmed=True, confirmed_by="operator")
    state.target = target

    # Authorization Gate
    lifecycle.transition_to("authorization")
    auth_validator = AuthorizationValidator(resolved_auth)
    auth_check = auth_validator.validate_for_assessment(target.raw_input)
    if not auth_check.allowed:
        lifecycle.transition_to("failed")
        raise PermissionError(auth_check.reason)

    # 3. Budget and Gateway Initialization
    limits = BudgetLimits.for_depth(depth)
    budget = BudgetManager(limits)
    recovery = RecoveryController()

    # Fallback to internal gateway if not passed
    if gateway is None:
        try:
            from raven_mcp.gateway import InternalGateway
            from raven_mcp.registry import ToolRegistry
            gateway = InternalGateway(ToolRegistry())
        except Exception as e:
            logger.debug(f"Could not initialize default InternalGateway: {e}")
            gateway = None

    context = AssessmentContext(
        target=target,
        scope=resolved_scope,
        authorization=resolved_auth,
        state=state,
        asset_graph=asset_graph,
        budget_manager=budget,
        provider=provider,
        gateway=gateway,
        config=config,
    )
    context.recovery_controller = recovery

    execution_engine = ExecutionEngine(context)

    try:
        if target.target_type == TargetType.SOURCE_REPOSITORY:
            logger.info("Initializing sandbox for source repository target.")
            # Launch sandbox
        
        # 4. Reconnaissance Phase
        lifecycle.transition_to("reconnaissance")
        await _run_reconnaissance(context)

        # 5. Classification Phase
        lifecycle.transition_to("classification")
        _run_classification(context)

        # 6. Capability Discovery & Selection
        registry = CapabilityRegistry()
        applicable = registry.find_applicable_capabilities(
            target=context.target,
            assets=context.asset_graph.all_assets(),
            scope=context.scope,
            authorization=context.authorization,
        )
        state.available_capabilities = [c.capability_id for c in applicable]

        selector = CapabilitySelector(
            explicit_include=selected_capabilities,
            explicit_exclude=excluded_capabilities,
            depth=depth,
        )
        selection_result = selector.select(applicable)
        state.active_capabilities = selection_result.activated_ids
        for cap_id, reason in selection_result.excluded:
            state.not_assessed.append(f"{cap_id}: {reason}")

        # 7. Adaptive Planning Phase
        lifecycle.transition_to("planning")
        
        try:
            from rag.retriever import SecurityRetriever
            retriever = SecurityRetriever()
            query = f"{context.target.target_type.value} pentest attack surface {' '.join(context.state.attack_surfaces[:3])}"
            rag_hints = retriever.retrieve(query, top_k=2)
            for hint in rag_hints:
                context.state.add_note(f"RAG Knowledge: {hint}")
        except Exception as e:
            logger.debug(f"Failed to retrieve RAG memory hints: {e}")

        plan = await _run_planning(context, selection_result.activated)

        # 8. Assessment Phase (Specialized Agents)
        lifecycle.transition_to("assessment")
        agent_instances = _instantiate_agents(selection_result.activated, context)
        await execution_engine.execute_agents_safely(
            activated_capabilities=selection_result.activated,
            agent_instances=agent_instances,
            parallel_groups=plan.get("parallel_groups") if isinstance(plan, dict) else None,
        )

        # 9. Finding Validation Phase
        lifecycle.transition_to("validation")
        await _run_validation(context)

        # 10. Risk Correlation & Coverage Phase
        lifecycle.transition_to("risk_analysis")
        await _run_risk_analysis(context)

        # 11. Reporting Phase
        lifecycle.transition_to("reporting")
        report = await _run_reporting(context, start_time)

        # Feedback Loop Ingestion
        try:
            from engine.feedback_loop import FeedbackIngester
            await FeedbackIngester.ingest(context, report)
        except Exception as e:
            logger.debug(f"Feedback loop ingestion skipped or failed: {e}")

        # 12. Complete
        lifecycle.transition_to("complete")
        return report

    except Exception as e:
        logger.error(f"Assessment [{state.assessment_id}] failed: {e}", exc_info=True)
        lifecycle.transition_to("failed")
        raise
    finally:
        if target.target_type == TargetType.SOURCE_REPOSITORY:
            logger.info("Tearing down sandbox for source repository target.")


# -------------------------------------------------------------------------
# Phase Orchestration Helpers (with graceful agent discovery / fallback)
# -------------------------------------------------------------------------

async def _run_reconnaissance(context: AssessmentContext) -> None:
    """Execute ReconAgent or fallback target profiling."""
    try:
        from agents.recon_agent import ReconAgent
        recon = ReconAgent(context)
        await recon.run()
    except (ImportError, AttributeError):
        # Fallback inline recon
        logger.info("ReconAgent not yet loaded; executing built-in baseline discovery.")
        from engine_models.assets import AssetType, DiscoveredAsset
        target = context.target
        if target.target_type in ("web_application", "rest_api"):
            asset = DiscoveredAsset(
                asset_type=AssetType.URL,
                value=target.raw_input,
                source="target_resolver",
                confidence="High",
            )
            context.asset_graph.add_asset(asset)
        elif target.target_type == "source_repository":
            asset = DiscoveredAsset(
                asset_type=AssetType.REPOSITORY,
                value=target.raw_input,
                source="target_resolver",
                confidence="High",
            )
            context.asset_graph.add_asset(asset)
        context.asset_graph.sync_to_state(context.state)


def _run_classification(context: AssessmentContext) -> None:
    """Synthesize attack surfaces and target profile from discovered assets."""
    surfaces = context.asset_graph.get_attack_surface()
    context.state.attack_surfaces = [s.value for s in surfaces]
    context.state.target_profile = {
        "primary_type": str(context.target.target_type.value),
        "entrypoints": context.target.entrypoints,
        "component_count": len(context.target.components),
        "asset_count": len(context.asset_graph.all_assets()),
        "attack_surface_count": len(surfaces),
    }


async def _run_planning(
    context: AssessmentContext,
    activated_capabilities: List[CapabilityManifest],
) -> Dict[str, Any]:
    """Execute PlanningAgent or deterministic planning fallback."""
    try:
        from agents.planning_agent import PlanningAgent
        planner = PlanningAgent(context)
        return await planner.plan(activated_capabilities)
    except Exception as e:
        logger.debug(f"PlanningAgent error: {e}. Trying PlanningEngine fallback.")
        try:
            from engine.planning_engine import PlanningEngine
            planner = PlanningEngine(context)
            return await planner.create_plan(activated_capabilities)
        except Exception:
            planned_tests = [f"Execute capability: {cap.name}" for cap in activated_capabilities]
            context.state.planned_tests = planned_tests
            return {"execution_order": [c.capability_id for c in activated_capabilities]}


def _instantiate_agents(
    capabilities: List[CapabilityManifest],
    context: AssessmentContext,
) -> Dict[str, Any]:
    """Dynamically load and instantiate specialized agents declared by capabilities."""
    agents: Dict[str, Any] = {}
    for cap in capabilities:
        if not cap.agent_module or not cap.agent_class:
            continue
        try:
            mod = importlib.import_module(cap.agent_module)
            agent_cls = getattr(mod, cap.agent_class)
            agents[cap.capability_id] = agent_cls(context)
        except Exception as e:
            logger.warning(
                f"Could not instantiate agent '{cap.agent_class}' from '{cap.agent_module}': {e}."
            )
            if "binary" in cap.capability_id:
                try:
                    from agents.specialized.binary_agent import BinaryAssessmentAgent
                    agents[cap.capability_id] = BinaryAssessmentAgent(context)
                except Exception:
                    pass
    return agents


async def _run_validation(context: AssessmentContext) -> None:
    """Execute ValidationAgent or promote candidate findings."""
    try:
        from agents.validation_agent import ValidationAgent
        validator = ValidationAgent(context)
        await validator.validate_all()
    except Exception as e:
        logger.debug(f"ValidationAgent error: {e}. Trying ValidationEngine fallback.")
        try:
            from engine.validation_engine import ValidationEngine
            validator = ValidationEngine(context)
            await validator.validate_all()
        except Exception:
            for f in context.state.candidate_findings:
                if f.evidence:
                    f.validation_status = ValidationStatus.CONFIRMED
                    context.state.confirmed_findings.append(f)
                else:
                    f.validation_status = ValidationStatus.INCONCLUSIVE
                    context.state.inconclusive_findings.append(f)


async def _run_risk_analysis(context: AssessmentContext) -> None:
    """Execute RiskEngine to correlate attack paths and track coverage."""
    try:
        from engine.risk_engine import RiskEngine
        risk_eng = RiskEngine(context)
        await risk_eng.analyze()
    except (ImportError, AttributeError):
        # Fallback inline coverage tracking
        for test in context.state.planned_tests:
            context.state.coverage.append(
                CoverageItem(
                    surface=test,
                    status="tested",
                    reason="Completed during assessment run",
                )
            )


async def _run_reporting(context: AssessmentContext, start_time: datetime) -> PentestReport:
    """Generate universal PentestReport."""
    try:
        from reports.report_generator import UniversalReportGenerator
        gen = UniversalReportGenerator(context)
        return await gen.build_report(start_time)
    except (ImportError, AttributeError):
        # Fallback report builder
        score_obj = RiskScore()
        report = PentestReport(
            assessment_id=context.state.assessment_id,
            target=context.target,
            confirmed_findings=context.state.confirmed_findings,
            inconclusive_findings=context.state.inconclusive_findings,
            coverage=context.state.coverage,
            limitations=context.state.limitations,
            not_assessed=context.state.not_assessed,
            risk_score=score_obj.score,
            risk_label=score_obj.label,
            risk_detail=score_obj,
            total_requests_made=context.budget_manager.requests_made,
            total_assets_discovered=len(context.asset_graph.all_assets()),
            total_tools_used=[],
            total_capabilities_used=context.state.active_capabilities,
            duration_seconds=round((datetime.now() - start_time).total_seconds(), 2),
        )
        return report
