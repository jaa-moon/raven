"""
web/content_validators.py
--------------------------
Content-specific validators for sensitive-path findings.

Each validator inspects the actual response body/headers for the finding
type it targets, and returns a ``ValidationOutcome`` with an explicit
evidence-based state. A path being in a wordlist, or returning HTTP 200,
is never sufficient on its own — see ``README`` in the task description
this module implements.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from validation.classifiers import ClassifiedResponse, ResponseClass


class ValidationState(str, Enum):
    """Evidence-based confidence state for a discovered candidate path."""

    CANDIDATE = "candidate"        # path/behavior was discovered, nothing else known
    VALIDATED = "validated"        # validator ran and found *some* relevant evidence
    CONFIRMED = "confirmed"        # evidence satisfies the validator's confidence bar
    INCONCLUSIVE = "inconclusive"  # suspicious but not enough evidence either way
    PROTECTED = "protected"        # resource exists but access is restricted
    SPA_FALLBACK = "spa_fallback"  # matches the SPA baseline
    FALSE_POSITIVE = "false_positive"  # initial signal disproven by content inspection


@dataclass
class ValidationOutcome:
    state: ValidationState
    confidence: str  # "High" | "Medium" | "Low" | "None"
    evidence: list[str] = field(default_factory=list)
    reason: str = ""
    vulnerability_type: str = ""
    severity: str = "Info"

    @property
    def confirmed(self) -> bool:
        return self.state == ValidationState.CONFIRMED


# ── Shared helpers ─────────────────────────────────────────────────────────────

_ENV_LINE_RE = re.compile(
    r"^\s*[A-Z_][A-Z0-9_]*\s*=\s*.+$", re.M
)
_ENV_KEY_HINTS = re.compile(
    r"(SECRET|API_KEY|DATABASE_URL|DB_PASSWORD|PASSWORD|TOKEN|ACCESS_KEY|PRIVATE_KEY|AWS_)",
    re.I,
)


def _redact_env_line(line: str) -> str:
    """Return a KEY=<REDACTED> form so secrets never reach the report."""
    if "=" not in line:
        return line
    key, _, _value = line.partition("=")
    return f"{key.strip()}=<REDACTED>"


def _from_fallback(classification: ClassifiedResponse) -> Optional[ValidationOutcome]:
    """Short-circuit: never run content validation on an SPA fallback or
    a response class that isn't a candidate 2xx real-resource in the first place."""
    if classification.classification == ResponseClass.SPA_FALLBACK:
        return ValidationOutcome(
            state=ValidationState.SPA_FALLBACK,
            confidence="None",
            reason=classification.reason,
        )
    if classification.classification == ResponseClass.PROTECTED:
        return ValidationOutcome(
            state=ValidationState.PROTECTED,
            confidence="Medium",
            evidence=[f"HTTP {classification.status} response — access restricted."],
            reason=classification.reason,
        )
    if classification.classification in (
        ResponseClass.GENERIC_404,
        ResponseClass.SERVER_ERROR,
        ResponseClass.UNKNOWN,
    ):
        return ValidationOutcome(
            state=ValidationState.FALSE_POSITIVE,
            confidence="None",
            reason=classification.reason,
        )
    return None


# ── Git exposure ────────────────────────────────────────────────────────────────

def validate_git_exposure(classification: ClassifiedResponse, body: str) -> ValidationOutcome:
    short = _from_fallback(classification)
    if short:
        return short

    if classification.classification == ResponseClass.REDIRECT:
        return ValidationOutcome(
            state=ValidationState.INCONCLUSIVE,
            confidence="Low",
            reason="Path redirected instead of returning file content.",
        )

    is_html = "html" in classification.content_type.lower() or "<html" in body.lower()[:500]
    ref_match = re.search(r"^ref:\s*refs/(heads|tags)/\S+", body, re.M)
    is_git_binary_like = body[:4] == "DIRC"  # a raw .git/index would start with DIRC magic

    if is_html:
        return ValidationOutcome(
            state=ValidationState.SPA_FALLBACK if classification.status == 200 else ValidationState.FALSE_POSITIVE,
            confidence="None",
            reason="Response is HTML, not a git plaintext object — this is the frontend shell, not an exposed .git file.",
        )

    if ref_match or is_git_binary_like:
        return ValidationOutcome(
            state=ValidationState.CONFIRMED,
            confidence="High",
            evidence=[ref_match.group(0) if ref_match else "Binary git object signature detected."],
            reason="Response content matches git internal file format.",
            vulnerability_type="SensitiveFileExposure",
            severity="Critical",
        )

    return ValidationOutcome(
        state=ValidationState.INCONCLUSIVE,
        confidence="Low",
        reason="Non-HTML response but does not contain recognizable git file content.",
    )


# ── .env exposure ────────────────────────────────────────────────────────────────

def validate_env_exposure(classification: ClassifiedResponse, body: str) -> ValidationOutcome:
    short = _from_fallback(classification)
    if short:
        return short

    if classification.classification == ResponseClass.REDIRECT:
        return ValidationOutcome(
            state=ValidationState.INCONCLUSIVE,
            confidence="Low",
            reason="Path redirected instead of returning file content.",
        )

    is_html = "html" in classification.content_type.lower() or "<html" in body.lower()[:500]
    if is_html:
        return ValidationOutcome(
            state=ValidationState.SPA_FALLBACK if classification.status == 200 else ValidationState.FALSE_POSITIVE,
            confidence="None",
            reason="Response is HTML and does not contain dotenv-formatted content.",
        )

    env_lines = [ln for ln in body.splitlines() if _ENV_LINE_RE.match(ln)]

    if len(env_lines) >= 2:
        redacted = [_redact_env_line(ln) for ln in env_lines[:10]]
        has_sensitive_key = any(_ENV_KEY_HINTS.search(ln) for ln in env_lines)
        return ValidationOutcome(
            state=ValidationState.CONFIRMED,
            confidence="High",
            evidence=redacted,
            reason=(
                f"Response contains {len(env_lines)} environment-style KEY=VALUE lines"
                + (" including credential-shaped keys" if has_sensitive_key else "")
                + " (values redacted)."
            ),
            vulnerability_type="SensitiveFileExposure",
            severity="Critical",
        )

    return ValidationOutcome(
        state=ValidationState.INCONCLUSIVE,
        confidence="Low",
        reason="Non-HTML response but does not contain multiple environment-style key-value lines.",
    )


# ── Actuator / Spring Boot management endpoints ──────────────────────────────────

_ACTUATOR_FIELDS = ("status", "components", "propertySources", "diskSpace", "_links")


def validate_actuator_exposure(classification: ClassifiedResponse, body: str) -> ValidationOutcome:
    short = _from_fallback(classification)
    if short:
        return short

    if classification.classification == ResponseClass.REDIRECT:
        return ValidationOutcome(
            state=ValidationState.INCONCLUSIVE,
            confidence="Low",
            reason="Path redirected instead of returning actuator data.",
        )

    is_html = "html" in classification.content_type.lower() or "<html" in body.lower()[:500]
    if is_html:
        return ValidationOutcome(
            state=ValidationState.SPA_FALLBACK if classification.status == 200 else ValidationState.FALSE_POSITIVE,
            confidence="None",
            reason="Response is HTML, not an actuator JSON payload.",
        )

    if not classification.is_json:
        return ValidationOutcome(
            state=ValidationState.INCONCLUSIVE,
            confidence="Low",
            reason="Non-HTML response but not JSON either — no actuator-specific evidence.",
        )

    found_fields = [f for f in _ACTUATOR_FIELDS if f'"{f}"' in body]
    if found_fields:
        return ValidationOutcome(
            state=ValidationState.CONFIRMED,
            confidence="High",
            evidence=[f"JSON response contains actuator field(s): {', '.join(found_fields)}."],
            reason="Response matches Spring Boot actuator response shape.",
            vulnerability_type="ActuatorExposure",
            severity="High",
        )

    return ValidationOutcome(
        state=ValidationState.INCONCLUSIVE,
        confidence="Low",
        reason="JSON response but does not contain expected actuator fields.",
    )


# ── Admin / console panels ───────────────────────────────────────────────────────

_ADMIN_MARKERS_RE = re.compile(
    r"(admin\s*(login|panel|dashboard|console)|wp-admin|django administration|"
    r"grafana|kibana|phpmyadmin|adminer|control\s*panel)",
    re.I,
)


def validate_admin_panel(
    classification: ClassifiedResponse,
    body: str,
    baseline_title: str = "",
) -> ValidationOutcome:
    short = _from_fallback(classification)
    if short:
        return short

    if classification.classification == ResponseClass.REDIRECT:
        location = classification.redirect_location or ""
        if re.search(r"(login|signin|auth)", location, re.I):
            return ValidationOutcome(
                state=ValidationState.VALIDATED,
                confidence="Medium",
                evidence=[f"Redirects to '{location}' (login/auth path)."],
                reason="Redirect target suggests an authentication gate exists, but the panel itself was not directly observed.",
                vulnerability_type="AdminPanelExposed",
                severity="Medium",
            )
        return ValidationOutcome(
            state=ValidationState.INCONCLUSIVE,
            confidence="Low",
            reason=f"Redirects to '{location}', which is not clearly an auth/login target.",
        )

    if classification.title and baseline_title and classification.title == baseline_title:
        return ValidationOutcome(
            state=ValidationState.SPA_FALLBACK,
            confidence="None",
            reason="Page title matches the generic frontend shell title — no distinct admin content.",
        )

    marker_match = _ADMIN_MARKERS_RE.search(body) or _ADMIN_MARKERS_RE.search(classification.title)
    if marker_match:
        return ValidationOutcome(
            state=ValidationState.CONFIRMED,
            confidence="High" if classification.auth_indicator else "Medium",
            evidence=[f"Distinct admin-panel marker found: '{marker_match.group(0)}'."],
            reason="Response content contains admin/console-specific markers distinct from the site's generic pages.",
            vulnerability_type="AdminPanelExposed",
            severity="High",
        )

    if classification.auth_indicator:
        return ValidationOutcome(
            state=ValidationState.VALIDATED,
            confidence="Low",
            evidence=["Response contains authentication-related text but no distinct admin-panel markers."],
            reason="Weak signal only — authentication wording present but no confirmed admin interface content.",
        )

    return ValidationOutcome(
        state=ValidationState.INCONCLUSIVE,
        confidence="Low",
        reason="Generic page content with no admin-panel-specific evidence.",
    )


# ── Config files (wp-config.php, config.php, parameters.yml, ...) ───────────────

_CONFIG_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"define\s*\(\s*['\"]DB_(NAME|USER|PASSWORD|HOST)['\"]", re.I), "WordPress wp-config.php constant"),
    (re.compile(r"<\?php", re.I), "Raw PHP source"),
    (re.compile(r"^\s*(parameters|database_url|secret)\s*:", re.I | re.M), "YAML config key"),
    (re.compile(r"mysqli_connect|new\s+PDO\(", re.I), "PHP database connection call"),
]


def validate_config_file(classification: ClassifiedResponse, body: str) -> ValidationOutcome:
    short = _from_fallback(classification)
    if short:
        return short

    if classification.classification == ResponseClass.REDIRECT:
        return ValidationOutcome(
            state=ValidationState.INCONCLUSIVE,
            confidence="Low",
            reason="Path redirected instead of returning file content.",
        )

    is_html = "html" in classification.content_type.lower() or "<html" in body.lower()[:500]
    if is_html:
        return ValidationOutcome(
            state=ValidationState.SPA_FALLBACK if classification.status == 200 else ValidationState.FALSE_POSITIVE,
            confidence="None",
            reason="Response is HTML, not raw configuration-file content (PHP source is usually executed, not returned, "
                   "unless misconfigured — an HTML page here is almost always the SPA/app shell).",
        )

    for pattern, description in _CONFIG_SIGNATURES:
        m = pattern.search(body)
        if m:
            return ValidationOutcome(
                state=ValidationState.CONFIRMED,
                confidence="High",
                evidence=[f"{description}: '{m.group(0)[:120]}'"],
                reason="Response content matches a known configuration-file signature.",
                vulnerability_type="SensitiveFileExposure",
                severity="Critical",
            )

    return ValidationOutcome(
        state=ValidationState.INCONCLUSIVE,
        confidence="Low",
        reason="Non-HTML response but does not match any known configuration-file signature.",
    )



# ── API documentation / GraphQL ────────────────────────────────────────────────

def validate_api_docs(classification: ClassifiedResponse, body: str) -> ValidationOutcome:
    short = _from_fallback(classification)
    if short:
        return short
    if classification.classification == ResponseClass.REDIRECT:
        return ValidationOutcome(
            state=ValidationState.INCONCLUSIVE, confidence="Low",
            reason="Path redirected instead of returning API documentation.",
        )
    is_html = "html" in classification.content_type.lower() or "<html" in body.lower()[:500]
    if classification.is_json:
        if re.search(r'"(openapi|swagger)"\s*:', body) and '"paths"' in body:
            return ValidationOutcome(
                state=ValidationState.CONFIRMED, confidence="High",
                evidence=["JSON document declares an OpenAPI/Swagger version and a paths object."],
                reason="Machine-readable API specification is publicly readable.",
                vulnerability_type="APIDocumentationExposed", severity="Low",
            )
        if '"__schema"' in body:
            return ValidationOutcome(
                state=ValidationState.CONFIRMED, confidence="High",
                evidence=["GraphQL introspection returned a __schema object."],
                reason="GraphQL introspection is enabled.",
                vulnerability_type="GraphQLIntrospectionEnabled", severity="Low",
            )
    if is_html and re.search(r"swagger-ui|redoc|graphiql", body, re.I):
        return ValidationOutcome(
            state=ValidationState.CONFIRMED, confidence="Medium",
            evidence=["HTML page embeds an interactive API documentation UI."],
            reason="Interactive API documentation UI is publicly reachable.",
            vulnerability_type="APIDocumentationExposed", severity="Low",
        )
    return ValidationOutcome(
        state=ValidationState.INCONCLUSIVE, confidence="Low",
        reason="Response does not contain recognizable API documentation.",
    )


# ── Directory listing ─────────────────────────────────────────────────────────

_LISTING_RE = re.compile(r"(?i)(<title>\s*(?:listing directory|index of)|<h1>\s*index of|parent directory)")


def validate_directory_listing(classification: ClassifiedResponse, body: str) -> ValidationOutcome:
    short = _from_fallback(classification)
    if short:
        return short
    if classification.classification == ResponseClass.REAL_RESOURCE and _LISTING_RE.search(body):
        return ValidationOutcome(
            state=ValidationState.CONFIRMED, confidence="High",
            evidence=["Response is an auto-generated directory index."],
            reason="Directory listing is enabled and publicly readable.",
            vulnerability_type="DirectoryListing", severity="Medium",
        )
    return ValidationOutcome(
        state=ValidationState.INCONCLUSIVE, confidence="Low",
        reason="Response does not look like a directory index.",
    )


CONTENT_CHECKS = {"directory_listing": validate_directory_listing}


# ── Dispatch ──────────────────────────────────────────────────────────────────

_GIT_PATHS = ("/.git/head", "/.git/config", "/.git/index")
_ENV_PATHS = ("/.env", "/.env.production", "/.env.local", "/.env.development", "/.env.test")
_ACTUATOR_PREFIX = "/actuator"
_ADMIN_PATHS = ("/admin", "/administrator", "/console", "/wp-admin", "/wp-login.php")
_API_DOC_PATHS = ("/swagger", "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs", "/v2/api-docs", "/graphql")
_CONFIG_PATHS = ("/wp-config.php", "/config.php", "/configuration.php", "/app/config/parameters.yml", "/phpinfo.php")


def get_validator_for_path(path: str) -> Optional[Callable[..., ValidationOutcome]]:
    """Return the content-specific validator function for *path*, if any."""
    lower = path.lower()
    if lower in _GIT_PATHS or lower.startswith("/.git/"):
        return validate_git_exposure
    if lower in _ENV_PATHS:
        return validate_env_exposure
    if lower.startswith(_ACTUATOR_PREFIX):
        return validate_actuator_exposure
    if lower in _ADMIN_PATHS:
        return validate_admin_panel
    if lower in _API_DOC_PATHS:
        return validate_api_docs
    if lower in _CONFIG_PATHS:
        return validate_config_file
    return None
