"""
engine_models/target.py
-----------------------
Universal target abstraction for Raven adaptive security assessment.

Replaces the web-specific ProjectProfile as the primary target representation.
A Target can represent any assessable digital system: web apps, APIs, binaries,
containers, cloud accounts, networks, repositories, firmware, and hybrid systems.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    """Exhaustive classification of assessable target types."""

    WEB_APPLICATION = "web_application"
    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    MOBILE_BACKEND = "mobile_backend"
    DESKTOP_APPLICATION = "desktop_application"
    LOCAL_APPLICATION = "local_application"
    CLI_APPLICATION = "cli_application"
    SOURCE_REPOSITORY = "source_repository"
    LIBRARY = "library"
    NATIVE_BINARY = "native_binary"
    NETWORK_SERVICE = "network_service"
    NETWORK_RANGE = "network_range"
    DATABASE = "database"
    MESSAGE_BROKER = "message_broker"
    CONTAINER = "container"
    CONTAINER_IMAGE = "container_image"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    CLOUD_ACCOUNT = "cloud_account"
    CLOUD_RESOURCE = "cloud_resource"
    SERVERLESS_FUNCTION = "serverless_function"
    INFRASTRUCTURE_AS_CODE = "infrastructure_as_code"
    CI_CD_PIPELINE = "ci_cd_pipeline"
    OPERATING_SYSTEM = "operating_system"
    FIRMWARE = "firmware"
    EMBEDDED_DEVICE = "embedded_device"
    SMART_CONTRACT = "smart_contract"
    PROTOCOL = "protocol"
    HYBRID_SYSTEM = "hybrid_system"
    UNKNOWN = "unknown"


class TargetComponent(BaseModel):
    """
    A single logical component within a target system.

    Hybrid targets contain multiple components connected by dependencies.
    Example: a web frontend → REST API → database → cloud infrastructure.
    """

    component_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    component_type: str = ""
    target_type: Optional[TargetType] = None
    name: str = ""
    location: str = ""

    parent_component_id: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)

    technologies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Target(BaseModel):
    """
    Universal target model for any assessable digital system.

    This replaces the web-specific ProjectProfile as the primary input
    to the assessment engine. Every assessment begins with a Target.
    """

    target_id: str = Field(default_factory=lambda: f"TGT-{uuid.uuid4().hex[:12]}")
    raw_input: str = ""

    target_type: TargetType = TargetType.UNKNOWN
    name: str = ""
    description: str = ""

    entrypoints: List[str] = Field(default_factory=list)
    components: List[TargetComponent] = Field(default_factory=list)

    # Scope and authorization are required but imported lazily to avoid circular deps
    scope: Optional[Any] = None  # engine_models.scope.Scope
    authorization: Optional[Any] = None  # engine_models.authorization.Authorization

    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    @property
    def is_hybrid(self) -> bool:
        """True if the target contains multiple distinct component types."""
        return self.target_type == TargetType.HYBRID_SYSTEM or len(self.components) > 1

    @property
    def component_types(self) -> List[str]:
        """List of unique component types in this target."""
        return list(set(c.component_type for c in self.components if c.component_type))

    def requires_sandbox(self) -> bool:
        """True if the target type typically requires isolated execution."""
        sandbox_types = {
            TargetType.WEB_APPLICATION,
            TargetType.REST_API,
            TargetType.GRAPHQL_API,
            TargetType.MOBILE_BACKEND,
            TargetType.LOCAL_APPLICATION,
            TargetType.CLI_APPLICATION,
            TargetType.DESKTOP_APPLICATION,
        }
        return self.target_type in sandbox_types

    def is_web_like(self) -> bool:
        """True if the target is web or API accessible."""
        return self.target_type in (
            TargetType.WEB_APPLICATION,
            TargetType.REST_API,
            TargetType.GRAPHQL_API,
            TargetType.MOBILE_BACKEND,
        )

    def is_local_like(self) -> bool:
        """True if target is a local repository, file, or binary."""
        return self.target_type in (
            TargetType.SOURCE_REPOSITORY,
            TargetType.LIBRARY,
            TargetType.LOCAL_APPLICATION,
            TargetType.NATIVE_BINARY,
        )

    def requires_network(self) -> bool:
        """True if assessment requires network access to the target."""
        network_types = {
            TargetType.WEB_APPLICATION,
            TargetType.REST_API,
            TargetType.GRAPHQL_API,
            TargetType.MOBILE_BACKEND,
            TargetType.NETWORK_SERVICE,
            TargetType.NETWORK_RANGE,
            TargetType.DATABASE,
            TargetType.MESSAGE_BROKER,
            TargetType.CLOUD_ACCOUNT,
            TargetType.CLOUD_RESOURCE,
            TargetType.KUBERNETES_CLUSTER,
            TargetType.SERVERLESS_FUNCTION,
            TargetType.EMBEDDED_DEVICE,
        }
        return self.target_type in network_types
