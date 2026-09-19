"""
capabilities/manifests/source_code_analysis.py
----------------------------------------------
Capability manifest for static source code security analysis.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

MANIFEST = CapabilityManifest(
    capability_id="source_code_analysis",
    name="Static Source Code Security Analysis (SAST)",
    description=(
        "Performs AST-driven structural and semantic security analysis on source code "
        "repositories. Discovers hardcoded vulnerabilities, unsanitized sinks, unsafe deserialization, "
        "path traversal, command injection, and architectural security anti-patterns."
    ),
    supported_target_types=[
        TargetType.SOURCE_REPOSITORY,
        TargetType.LIBRARY,
        TargetType.LOCAL_APPLICATION,
        TargetType.CLI_APPLICATION,
        TargetType.DESKTOP_APPLICATION,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.FILE,
        AssetType.DIRECTORY,
        AssetType.REPOSITORY,
        AssetType.FUNCTION,
        AssetType.CLASS,
        AssetType.MODULE,
        AssetType.ROUTE,
    ],
    required_tools=["read_file", "list_directory"],
    optional_tools=["compress_ast", "analyze_file"],
    agent_module="agents.specialized.source_code_agent",
    agent_class="SourceCodeAssessmentAgent",
    required_inputs=["repo_path"],
    produces_assets=[AssetType.FILE, AssetType.ROUTE, AssetType.FUNCTION],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
