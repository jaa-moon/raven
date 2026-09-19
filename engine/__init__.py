"""
engine/__init__.py
------------------
Core assessment engine for Raven v3.0.

Provides universal assessment orchestration, target resolution,
scope and authorization enforcement, execution lifecycle, and budget management.
"""

from engine.assessment_context import AssessmentContext
from engine.assessment_controller import run_assessment
from engine.asset_graph import AssetGraph
from engine.authorization_validator import AuthorizationValidator
from engine.budget_manager import BudgetLimits, BudgetManager
from engine.capability_selector import CapabilitySelector
from engine.execution_engine import ExecutionEngine
from engine.lifecycle_manager import LifecycleManager
from engine.recovery_controller import FailureType, RecoveryAction, RecoveryController
from engine.result_processor import ResultProcessor
from engine.scope_validator import ScopeValidator
from engine.target_resolver import TargetResolver

__all__ = [
    "run_assessment",
    "AssessmentContext",
    "AssetGraph",
    "ScopeValidator",
    "AuthorizationValidator",
    "BudgetManager",
    "BudgetLimits",
    "CapabilitySelector",
    "ExecutionEngine",
    "LifecycleManager",
    "RecoveryController",
    "FailureType",
    "RecoveryAction",
    "ResultProcessor",
    "TargetResolver",
]
