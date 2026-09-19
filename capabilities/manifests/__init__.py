"""
capabilities/manifests/__init__.py
----------------------------------
Registry of all built-in capability manifests in Raven v3.0.
"""

from typing import List

from capabilities.manifests.auth_identity_assessment import MANIFEST as AUTH_IDENTITY_MANIFEST
from capabilities.manifests.binary_analysis import MANIFEST as BINARY_MANIFEST
from capabilities.manifests.cloud_assessment import MANIFEST as CLOUD_MANIFEST
from capabilities.manifests.configuration_assessment import MANIFEST as CONFIG_MANIFEST
from capabilities.manifests.container_assessment import MANIFEST as CONTAINER_MANIFEST
from capabilities.manifests.database_assessment import MANIFEST as DATABASE_MANIFEST
from capabilities.manifests.dependency_analysis import MANIFEST as DEPENDENCY_MANIFEST
from capabilities.manifests.firmware_analysis import MANIFEST as FIRMWARE_MANIFEST
from capabilities.manifests.kubernetes_assessment import MANIFEST as KUBERNETES_MANIFEST
from capabilities.manifests.network_assessment import MANIFEST as NETWORK_MANIFEST
from capabilities.manifests.protocol_assessment import MANIFEST as PROTOCOL_MANIFEST
from capabilities.manifests.secrets_detection import MANIFEST as SECRETS_MANIFEST
from capabilities.manifests.smart_contract_analysis import MANIFEST as SMART_CONTRACT_MANIFEST
from capabilities.manifests.source_code_analysis import MANIFEST as SOURCE_CODE_MANIFEST
from capabilities.manifests.web_api_assessment import MANIFEST as WEB_API_MANIFEST
from engine_models.capabilities import CapabilityManifest

ALL_MANIFESTS: List[CapabilityManifest] = [
    WEB_API_MANIFEST,
    SOURCE_CODE_MANIFEST,
    AUTH_IDENTITY_MANIFEST,
    SECRETS_MANIFEST,
    DEPENDENCY_MANIFEST,
    NETWORK_MANIFEST,
    CONTAINER_MANIFEST,
    CLOUD_MANIFEST,
    KUBERNETES_MANIFEST,
    BINARY_MANIFEST,
    DATABASE_MANIFEST,
    FIRMWARE_MANIFEST,
    SMART_CONTRACT_MANIFEST,
    CONFIG_MANIFEST,
    PROTOCOL_MANIFEST,
]

__all__ = ["ALL_MANIFESTS"]
