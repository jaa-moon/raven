"""
capabilities/manifests/kubernetes_assessment.py
-----------------------------------------------
Capability manifest for Kubernetes Cluster & Workload Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate external K8s security tools (e.g. kube-bench, kube-hunter, Checkov)
MANIFEST = CapabilityManifest(
    capability_id="kubernetes_assessment",
    name="Kubernetes Cluster & Workload Security Assessment",
    description=(
        "Evaluates Kubernetes cluster RBAC, pod security standards, service account "
        "privileges, hostpath mounts, network policies, and API server exposure."
    ),
    supported_target_types=[
        TargetType.KUBERNETES_CLUSTER,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.POD,
        AssetType.NAMESPACE,
        AssetType.DEPLOYMENT,
        AssetType.CONFIG_MAP,
    ],
    required_tools=[],
    optional_tools=["audit_k8s_rbac", "check_pod_security"],
    agent_module="agents.specialized.kubernetes_agent",
    agent_class="KubernetesAssessmentAgent",
    required_inputs=["kubeconfig"],
    produces_assets=[AssetType.POD, AssetType.NAMESPACE],
    risk_level="moderate",
    supports_passive_mode=True,
    supports_active_mode=True,
    supports_authenticated_mode=True,
    prerequisites=[],
    exclusions=[],
)
