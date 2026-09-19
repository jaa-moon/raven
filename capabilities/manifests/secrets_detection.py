"""
capabilities/manifests/secrets_detection.py
-------------------------------------------
Capability manifest for Hardcoded Secret and Credential Detection.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

MANIFEST = CapabilityManifest(
    capability_id="secrets_detection",
    name="Hardcoded Secret & Credential Detection",
    description=(
        "Scans repositories, configuration files, and server responses for high-entropy "
        "tokens, API keys, private keys, database credentials, and cloud provider secrets."
    ),
    supported_target_types=[
        TargetType.SOURCE_REPOSITORY,
        TargetType.LOCAL_APPLICATION,
        TargetType.CONTAINER_IMAGE,
        TargetType.INFRASTRUCTURE_AS_CODE,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.FILE,
        AssetType.SECRET,
        AssetType.API_KEY,
        AssetType.CERTIFICATE,
        AssetType.CREDENTIAL,
    ],
    required_tools=["scan_secrets"],
    optional_tools=["read_file"],
    agent_module="agents.specialized.secrets_agent",
    agent_class="SecretsAssessmentAgent",
    required_inputs=["repo_path"],
    produces_assets=[AssetType.SECRET, AssetType.API_KEY, AssetType.CREDENTIAL],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
