"""
capabilities/manifests/smart_contract_analysis.py
-------------------------------------------------
Capability manifest for Smart Contract Security Analysis.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

# TODO: Integrate external smart contract analyzers (e.g. Slither, Mythril)
MANIFEST = CapabilityManifest(
    capability_id="smart_contract_analysis",
    name="Smart Contract Security Analysis",
    description=(
        "Analyzes EVM / Solidity / Vyper / Rust smart contracts for reentrancy, integer overflows, "
        "oracle manipulation, unvalidated calls, frontrunning, and access control bugs."
    ),
    supported_target_types=[
        TargetType.SMART_CONTRACT,
        TargetType.SOURCE_REPOSITORY,
    ],
    supported_asset_types=[
        AssetType.SMART_CONTRACT,
        AssetType.CONTRACT_FUNCTION,
    ],
    required_tools=[],
    optional_tools=["analyze_solidity", "check_reentrancy"],
    agent_module="agents.specialized.smart_contract_agent",
    agent_class="SmartContractAssessmentAgent",
    required_inputs=["contract_source_or_address"],
    produces_assets=[AssetType.SMART_CONTRACT, AssetType.CONTRACT_FUNCTION],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
