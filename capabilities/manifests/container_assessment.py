"""
capabilities/manifests/container_assessment.py
----------------------------------------------
Capability manifest for Container & Image Security Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate external container vulnerability scanner (e.g. Trivy, Grype)
MANIFEST = CapabilityManifest(
    capability_id="container_assessment",
    name="Container & Image Security Assessment",
    description=(
        "Inspects container images, Dockerfiles, layer history, and base OS packages "
        "for known vulnerabilities, root execution hazards, and privilege escalations."
    ),
    supported_target_types=[
        TargetType.CONTAINER,
        TargetType.CONTAINER_IMAGE,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.CONTAINER,
        AssetType.IMAGE,
        AssetType.FILE,
    ],
    required_tools=[],
    optional_tools=["inspect_container_image"],
    agent_module="agents.specialized.container_agent",
    agent_class="ContainerAssessmentAgent",
    required_inputs=["image_name"],
    produces_assets=[AssetType.IMAGE, AssetType.PACKAGE if hasattr(AssetType, "PACKAGE") else AssetType.DEPENDENCY],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=True,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
