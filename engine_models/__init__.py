"""
engine_models/__init__.py
-------------------------
Universal data models for Raven v3.0 adaptive security assessment engine.

Re-exports all public model classes for convenient importing:
    from engine_models import Target, Finding, AssessmentState, ...
"""

# Target abstraction
from engine_models.target import Target, TargetComponent, TargetType

# Scope and authorization
from engine_models.scope import Scope
from engine_models.authorization import Authorization

# Asset graph
from engine_models.assets import AssetType, DiscoveredAsset, AssetRelationship

# Capabilities
from engine_models.capabilities import CapabilityManifest

# Assessment state
from engine_models.state import AssessmentState

# Actions and results
from engine_models.actions import AgentAction
from engine_models.results import NormalizedToolResult

# Hypotheses
from engine_models.hypotheses import Hypothesis

# Findings and evidence
from engine_models.findings import Finding, EvidenceItem, ValidationStatus

# Validation
from engine_models.validation import ValidationResult

# Coverage
from engine_models.coverage import CoverageItem

# Risk
from engine_models.risk import AttackPath, AttackPathStep, RiskScore

# Report
from engine_models.report import PentestReport

__all__ = [
    # Target
    "Target",
    "TargetComponent",
    "TargetType",
    # Scope / Auth
    "Scope",
    "Authorization",
    # Assets
    "AssetType",
    "DiscoveredAsset",
    "AssetRelationship",
    # Capabilities
    "CapabilityManifest",
    # State
    "AssessmentState",
    # Actions / Results
    "AgentAction",
    "NormalizedToolResult",
    # Hypotheses
    "Hypothesis",
    # Findings
    "Finding",
    "EvidenceItem",
    "ValidationStatus",
    # Validation
    "ValidationResult",
    # Coverage
    "CoverageItem",
    # Risk
    "AttackPath",
    "AttackPathStep",
    "RiskScore",
    # Report
    "PentestReport",
]
