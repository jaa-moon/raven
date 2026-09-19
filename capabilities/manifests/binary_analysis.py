"""
capabilities/manifests/binary_analysis.py
-----------------------------------------
Capability manifest for Native Binary & Executable Analysis.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate external binary analysis tools (e.g. Ghidra, radare2, checksec)
MANIFEST = CapabilityManifest(
    capability_id="binary_analysis",
    name="Native Binary & Reverse Engineering Assessment",
    description=(
        "Analyzes compiled executables and shared libraries. Checks binary hardening flags "
        "(ASLR, DEP/NX, Stack Canaries, RELRO), string tables, imported APIs, and known buffer overflows."
    ),
    supported_target_types=[
        TargetType.NATIVE_BINARY,
        TargetType.DESKTOP_APPLICATION,
        TargetType.LOCAL_APPLICATION,
        TargetType.CLI_APPLICATION,
        TargetType.LIBRARY,
    ],
    supported_asset_types=[
        AssetType.BINARY,
        AssetType.PROCESS,
        AssetType.LIBRARY,
        AssetType.SYMBOL,
    ],
    required_tools=[],
    optional_tools=["checksec", "extract_strings", "disassemble_binary"],
    agent_module="agents.specialized.binary_agent",
    agent_class="BinaryAssessmentAgent",
    required_inputs=["binary_path"],
    produces_assets=[AssetType.BINARY, AssetType.SYMBOL],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
