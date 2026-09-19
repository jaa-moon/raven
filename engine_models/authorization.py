"""
engine_models/authorization.py
------------------------------
Authorization model for Raven adaptive security assessment.

Every assessment must have explicit authorization before any tool executes.
Stores confirmation, credentials, and authorization metadata.
"""

from __future__ import annotations

from typing import Dict

from pydantic import BaseModel, Field


class Authorization(BaseModel):
    """
    Explicit authorization record for a security assessment.

    No assessment can proceed unless ``confirmed`` is True.
    Credentials are stored in-memory only and never persisted to disk
    by the state serializer.
    """

    confirmed: bool = False
    confirmed_by: str = ""
    authorization_type: str = ""  # e.g., "written_authorization", "bug_bounty", "self_owned"
    authorization_reference: str = ""  # Reference document or ticket number

    # Credentials for authenticated testing (in-memory only, not persisted)
    credentials: Dict[str, str] = Field(default_factory=dict)
    api_keys: Dict[str, str] = Field(default_factory=dict)
    certificates: Dict[str, str] = Field(default_factory=dict)

    notes: str = ""

    def has_credentials(self) -> bool:
        """True if any authentication credentials are available."""
        return bool(self.credentials or self.api_keys or self.certificates)

    def redacted_summary(self) -> str:
        """Return a safe-to-log summary without exposing credential values."""
        cred_types = []
        if self.credentials:
            cred_types.append(f"{len(self.credentials)} username/password pair(s)")
        if self.api_keys:
            cred_types.append(f"{len(self.api_keys)} API key(s)")
        if self.certificates:
            cred_types.append(f"{len(self.certificates)} certificate(s)")

        cred_summary = ", ".join(cred_types) if cred_types else "none"
        return (
            f"Authorization(confirmed={self.confirmed}, "
            f"type={self.authorization_type!r}, "
            f"credentials=[{cred_summary}])"
        )
