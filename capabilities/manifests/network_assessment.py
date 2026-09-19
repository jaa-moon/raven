"""
capabilities/manifests/network_assessment.py
--------------------------------------------
Capability manifest for Network & Port Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

MANIFEST = CapabilityManifest(
    capability_id="network_assessment",
    name="Network & Port Security Assessment",
    description=(
        "Discovers exposed network services, open TCP/UDP ports, service banners, "
        "and insecure protocol configurations across hosts and IP ranges."
    ),
    supported_target_types=[
        TargetType.NETWORK_SERVICE,
        TargetType.NETWORK_RANGE,
        TargetType.WEB_APPLICATION,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.HOST,
        AssetType.PORT,
        AssetType.SERVICE,
        AssetType.IP_ADDRESS,
        AssetType.PROTOCOL,
    ],
    required_tools=["scan_ports"],
    optional_tools=["banner_grab"],
    agent_module="agents.specialized.network_agent",
    agent_class="NetworkAssessmentAgent",
    required_inputs=["host"],
    produces_assets=[AssetType.PORT, AssetType.SERVICE],
    risk_level="moderate",
    supports_passive_mode=False,
    supports_active_mode=True,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
