"""
engine_models/assets.py
-----------------------
Universal asset discovery models for Raven adaptive security assessment.

Assets represent anything discovered during reconnaissance or assessment:
URLs, endpoints, ports, files, containers, IAM roles, secrets, etc.
Assets form a directed graph with typed relationships.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    """Classification of discoverable assets across all target types."""

    # Web / API
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    FORM = "form"
    HEADER = "header"
    COOKIE = "cookie"

    # Network
    PORT = "port"
    SERVICE = "service"
    HOST = "host"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    PROTOCOL = "protocol"

    # Source code
    FILE = "file"
    DIRECTORY = "directory"
    REPOSITORY = "repository"
    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"
    ROUTE = "route"
    DEPENDENCY = "dependency"

    # Binary
    BINARY = "binary"
    PROCESS = "process"
    LIBRARY = "library"
    SYMBOL = "symbol"

    # Container / K8s
    CONTAINER = "container"
    IMAGE = "image"
    POD = "pod"
    NAMESPACE = "namespace"
    DEPLOYMENT = "deployment"
    CONFIG_MAP = "config_map"

    # Cloud
    CLOUD_RESOURCE = "cloud_resource"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    SECURITY_GROUP = "security_group"

    # Data
    DATABASE = "database"
    TABLE = "table"
    SCHEMA = "schema"
    BUCKET = "bucket"
    QUEUE = "queue"

    # Secrets / Identity
    SECRET = "secret"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    API_KEY = "api_key"
    CREDENTIAL = "credential"

    # Firmware / Embedded
    FIRMWARE_COMPONENT = "firmware_component"
    FILESYSTEM = "filesystem"

    # Blockchain
    SMART_CONTRACT = "smart_contract"
    CONTRACT_FUNCTION = "contract_function"

    # Generic
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class DiscoveredAsset(BaseModel):
    """
    A single asset discovered during reconnaissance or assessment.

    Assets are nodes in the asset graph. Each asset has a type, a value
    (the actual identifier — URL, IP, file path, etc.), and optional
    linkage to a target component and parent asset.
    """

    asset_id: str = Field(default_factory=lambda: f"AST-{uuid.uuid4().hex[:8]}")
    asset_type: AssetType = AssetType.UNKNOWN
    value: str = ""

    component_id: Optional[str] = None
    parent_asset_id: Optional[str] = None

    source: str = ""  # Which agent/tool discovered this asset
    confidence: str = "Medium"  # High, Medium, Low

    metadata: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    @property
    def display_name(self) -> str:
        """Human-readable summary of the asset."""
        return f"[{self.asset_type.value}] {self.value}"


class AssetRelationship(BaseModel):
    """
    A directed edge between two assets in the asset graph.

    Relationships model how assets connect: a frontend calls an API endpoint,
    a container runs a service, a source file defines a function, an IAM role
    grants access to a cloud resource, etc.
    """

    relationship_id: str = Field(default_factory=lambda: f"REL-{uuid.uuid4().hex[:8]}")
    source_asset_id: str = ""
    target_asset_id: str = ""

    relationship_type: str = ""  # e.g., "calls", "runs", "defines", "listens_on", "grants_access_to"
    confidence: str = "Medium"  # High, Medium, Low
    evidence_ids: List[str] = Field(default_factory=list)

    metadata: Dict[str, Any] = Field(default_factory=dict)
