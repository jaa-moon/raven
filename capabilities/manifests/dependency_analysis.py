"""
capabilities/manifests/dependency_analysis.py
---------------------------------------------
Capability manifest for Software Composition Analysis (SCA) & Dependency Audit.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

MANIFEST = CapabilityManifest(
    capability_id="dependency_analysis",
    name="Software Composition Analysis & Vulnerable Dependencies",
    description=(
        "Audits project package manifests (requirements.txt, package.json, pom.xml, go.mod, etc.) "
        "to identify known CVEs, outdated packages, and license/supply-chain risks."
    ),
    supported_target_types=[
        TargetType.SOURCE_REPOSITORY,
        TargetType.LIBRARY,
        TargetType.LOCAL_APPLICATION,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.FILE,
        AssetType.DEPENDENCY,
    ],
    required_tools=["audit_dependencies"],
    optional_tools=["read_file"],
    agent_module="agents.specialized.dependency_agent",
    agent_class="DependencyAssessmentAgent",
    required_inputs=["repo_path"],
    produces_assets=[AssetType.DEPENDENCY],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
