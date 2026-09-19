"""
capabilities/manifests/firmware_analysis.py
-------------------------------------------
Capability manifest for Embedded Device & Firmware Security Analysis.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate external firmware extraction & analysis tools (e.g. binwalk, emba)
MANIFEST = CapabilityManifest(
    capability_id="firmware_analysis",
    name="Embedded Device & Firmware Security Analysis",
    description=(
        "Unpacks firmware images, extracts embedded filesystems, analyzes kernel configurations, "
        "and identifies hardcoded vendor credentials, debugging backdoors, and outdated packages."
    ),
    supported_target_types=[
        TargetType.FIRMWARE,
        TargetType.EMBEDDED_DEVICE,
    ],
    supported_asset_types=[
        AssetType.FIRMWARE_COMPONENT,
        AssetType.FILESYSTEM,
        AssetType.SECRET,
        AssetType.BINARY,
    ],
    required_tools=[],
    optional_tools=["extract_firmware", "scan_firmware_credentials"],
    agent_module="agents.specialized.firmware_agent",
    agent_class="FirmwareAssessmentAgent",
    required_inputs=["firmware_path"],
    produces_assets=[AssetType.FIRMWARE_COMPONENT, AssetType.FILESYSTEM],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
