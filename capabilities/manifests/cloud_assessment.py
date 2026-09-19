"""
capabilities/manifests/cloud_assessment.py
------------------------------------------
Capability manifest for Cloud Infrastructure & IAM Security Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate external cloud security audit tools (e.g. ScoutSuite, Prowler, CloudSploit)
MANIFEST = CapabilityManifest(
    capability_id="cloud_assessment",
    name="Cloud Infrastructure & IAM Security Assessment",
    description=(
        "Audits cloud configuration, IAM policies, public storage buckets, "
        "security group exposure, and excessive privilege delegations across AWS/GCP/Azure."
    ),
    supported_target_types=[
        TargetType.CLOUD_ACCOUNT,
        TargetType.CLOUD_RESOURCE,
        TargetType.SERVERLESS_FUNCTION,
        TargetType.INFRASTRUCTURE_AS_CODE,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.CLOUD_RESOURCE,
        AssetType.IAM_ROLE,
        AssetType.IAM_POLICY,
        AssetType.SECURITY_GROUP,
        AssetType.BUCKET,
    ],
    required_tools=[],
    optional_tools=["audit_cloud_iam", "scan_public_buckets"],
    agent_module="agents.specialized.cloud_agent",
    agent_class="CloudAssessmentAgent",
    required_inputs=["cloud_account_id"],
    produces_assets=[AssetType.CLOUD_RESOURCE, AssetType.IAM_ROLE],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=True,
    prerequisites=[],
    exclusions=[],
)
