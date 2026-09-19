"""
capabilities/manifests/database_assessment.py
---------------------------------------------
Capability manifest for Database Security Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate external database audit tools (e.g. sqlmap, db-auditor)
MANIFEST = CapabilityManifest(
    capability_id="database_assessment",
    name="Database Security & Configuration Assessment",
    description=(
        "Audits database instances, default credentials, user privileges, "
        "unencrypted storage, and SQL exposure vectors."
    ),
    supported_target_types=[
        TargetType.DATABASE,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.DATABASE,
        AssetType.TABLE,
        AssetType.SCHEMA,
        AssetType.SERVICE,
    ],
    required_tools=[],
    optional_tools=["audit_database_config", "check_db_auth"],
    agent_module="agents.specialized.database_agent",
    agent_class="DatabaseAssessmentAgent",
    required_inputs=["db_connection_str"],
    produces_assets=[AssetType.DATABASE, AssetType.TABLE],
    risk_level="moderate",
    supports_passive_mode=True,
    supports_active_mode=True,
    supports_authenticated_mode=True,
    prerequisites=[],
    exclusions=[],
)
