"""
capabilities/manifests/protocol_assessment.py
---------------------------------------------
Capability manifest for Custom & Industrial Protocol Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate protocol fuzzing and dissector tools (e.g. Scapy, Boofuzz)
MANIFEST = CapabilityManifest(
    capability_id="protocol_assessment",
    name="Protocol & Transport Layer Security Assessment",
    description=(
        "Analyzes transport layer security (TLS/SSL cipher suites, certificates), "
        "and custom binary or network protocol implementations."
    ),
    supported_target_types=[
        TargetType.PROTOCOL,
        TargetType.NETWORK_SERVICE,
        TargetType.WEB_APPLICATION,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.PROTOCOL,
        AssetType.SERVICE,
        AssetType.CERTIFICATE,
    ],
    required_tools=[],
    optional_tools=["check_tls_ciphers"],
    agent_module="agents.specialized.protocol_agent",
    agent_class="ProtocolAssessmentAgent",
    required_inputs=["host_and_port"],
    produces_assets=[AssetType.PROTOCOL, AssetType.CERTIFICATE],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=True,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
