"""
engine/authorization_validator.py
---------------------------------
Universal authorization validation engine for Raven adaptive security assessment.

Validates that:
1. Explicit authorization has been confirmed prior to starting any scan or tool execution
2. Appropriate credentials exist if authenticated testing is required
3. Clear audit records are maintained without credential exposure
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from engine_models.authorization import Authorization


@dataclass
class AuthorizationCheckResult:
    """Outcome of authorization verification."""

    allowed: bool
    reason: str
    confirmed_by: str = ""
    auth_type: str = ""
    has_credentials: bool = False
    missing_requirements: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.allowed


class AuthorizationValidator:
    """
    Ensures ethical and authorized execution of security assessments.
    Enforces authorization gates at assessment startup and before authenticated actions.
    """

    def __init__(self, authorization: Optional[Authorization] = None) -> None:
        self.authorization: Authorization = authorization or Authorization()

    def validate_for_assessment(
        self,
        target_identifier: str,
        require_active_authorization: bool = False,
    ) -> AuthorizationCheckResult:
        """
        Verify that the assessment is legally and procedurally authorized to proceed.
        """
        if not self.authorization.confirmed:
            return AuthorizationCheckResult(
                allowed=False,
                reason=(
                    f"Assessment on '{target_identifier}' aborted: authorization has not been confirmed. "
                    "Raven requires explicit authorization confirmation (--authorized or authorization profile)."
                ),
                missing_requirements=["authorization.confirmed"],
            )

        confirmed_by = self.authorization.confirmed_by or "unspecified_operator"
        auth_type = self.authorization.authorization_type or "standard_assessment"

        return AuthorizationCheckResult(
            allowed=True,
            reason=f"Assessment authorized by '{confirmed_by}' under '{auth_type}'.",
            confirmed_by=confirmed_by,
            auth_type=auth_type,
            has_credentials=self.authorization.has_credentials(),
            details={
                "authorization_reference": self.authorization.authorization_reference,
                "notes": self.authorization.notes,
                "has_credentials": self.authorization.has_credentials(),
            },
        )

    def validate_authenticated_capability(
        self,
        capability_id: str,
        required_credential_type: Optional[str] = None,
    ) -> AuthorizationCheckResult:
        """
        Verify that adequate credentials are present for an authenticated capability or tool.
        """
        if not self.authorization.confirmed:
            return AuthorizationCheckResult(
                allowed=False,
                reason=f"Capability '{capability_id}' cannot run: assessment not authorized.",
                missing_requirements=["authorization.confirmed"],
            )

        missing = []
        if required_credential_type == "credentials" and not self.authorization.credentials:
            missing.append("credentials (username/password)")
        elif required_credential_type == "api_key" and not self.authorization.api_keys:
            missing.append("api_keys")
        elif required_credential_type == "certificate" and not self.authorization.certificates:
            missing.append("certificates")
        elif not self.authorization.has_credentials():
            missing.append("any authentication credential")

        if missing:
            return AuthorizationCheckResult(
                allowed=False,
                reason=(
                    f"Capability '{capability_id}' requires authentication, but no "
                    f"{', '.join(missing)} was supplied in authorization profile."
                ),
                confirmed_by=self.authorization.confirmed_by,
                auth_type=self.authorization.authorization_type,
                missing_requirements=missing,
            )

        return AuthorizationCheckResult(
            allowed=True,
            reason=f"Authentication requirements met for capability '{capability_id}'.",
            confirmed_by=self.authorization.confirmed_by,
            auth_type=self.authorization.authorization_type,
            has_credentials=True,
        )
