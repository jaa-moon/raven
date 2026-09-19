"""
tests/test_content_validators.py
----------------------------------
Regression tests for web.content_validators — content-specific evidence
requirements for git/env/actuator/admin/config-file findings.

These cover the required regression cases from the SPA-fallback-honesty
task: real exposures must be confirmed, SPA fallback / generic 200s must
not be, and protected/redirected responses must be classified honestly.
"""

from web.content_validators import (
    ValidationState,
    validate_actuator_exposure,
    validate_admin_panel,
    validate_config_file,
    validate_env_exposure,
    validate_git_exposure,
)
from web.response_classifier import ResponseClass, classify_response
from web.spa_fallback_detector import SPAFallbackDetector

SPA_SHELL = "<html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root></body></html>"


def _detector():
    detector = SPAFallbackDetector(
        fetcher=lambda p: (200, {"Content-Type": "text/html"}, SPA_SHELL)
    )
    detector.establish_baseline()
    return detector


# 1. A real exposed .env response is detected.
def test_real_exposed_env_response_is_confirmed():
    body = "DATABASE_URL=postgres://user:pass@localhost/db\nSECRET_KEY=supersecret\nAPI_KEY=abcdef123456\n"
    classification = classify_response("/.env", 200, {"Content-Type": "text/plain"}, body, _detector())
    outcome = validate_env_exposure(classification, body)
    assert outcome.state == ValidationState.CONFIRMED
    assert outcome.confirmed is True
    # Secrets must never appear in the evidence — only redacted key names.
    assert all("supersecret" not in e and "abcdef123456" not in e for e in outcome.evidence)
    assert any("REDACTED" in e for e in outcome.evidence)


# 2. A real exposed .git/HEAD response is detected.
def test_real_exposed_git_head_response_is_confirmed():
    body = "ref: refs/heads/main\n"
    classification = classify_response("/.git/HEAD", 200, {"Content-Type": "text/plain"}, body, _detector())
    outcome = validate_git_exposure(classification, body)
    assert outcome.state == ValidationState.CONFIRMED
    assert outcome.confirmed is True


# 3. A JSON actuator response is detected.
def test_json_actuator_response_is_confirmed():
    body = '{"status": "UP", "components": {"db": {"status": "UP"}}}'
    classification = classify_response(
        "/actuator/health", 200, {"Content-Type": "application/json"}, body, _detector()
    )
    outcome = validate_actuator_exposure(classification, body)
    assert outcome.state == ValidationState.CONFIRMED
    assert outcome.confirmed is True


# 4. An actual admin login page is detected.
def test_real_admin_login_page_is_confirmed():
    body = "<html><head><title>Admin Login</title></head><body><h1>Admin Panel Login</h1></body></html>"
    classification = classify_response("/admin", 200, {"Content-Type": "text/html"}, body, _detector())
    outcome = validate_admin_panel(classification, body, baseline_title="OWASP Juice Shop")
    assert outcome.state == ValidationState.CONFIRMED
    assert outcome.confirmed is True


# 5. A generic 200 HTML response is not confirmed.
def test_generic_200_html_response_is_not_confirmed_for_env():
    body = "<html><head><title>Some Page</title></head><body>Hello</body></html>"
    classification = classify_response("/.env", 200, {"Content-Type": "text/html"}, body, None)
    outcome = validate_env_exposure(classification, body)
    assert outcome.confirmed is False


# 6. A Juice Shop-style SPA fallback is not confirmed.
def test_juice_shop_spa_fallback_is_not_confirmed_for_any_validator():
    detector = _detector()
    classification = classify_response("/.env", 200, {"Content-Type": "text/html"}, SPA_SHELL, detector)
    assert classification.classification == ResponseClass.SPA_FALLBACK

    for validator, extra in [
        (validate_env_exposure, {}),
        (validate_git_exposure, {}),
        (validate_actuator_exposure, {}),
        (validate_config_file, {}),
    ]:
        outcome = validator(classification, SPA_SHELL, **extra)
        assert outcome.state == ValidationState.SPA_FALLBACK
        assert outcome.confirmed is False

    admin_outcome = validate_admin_panel(classification, SPA_SHELL, baseline_title="OWASP Juice Shop")
    assert admin_outcome.state == ValidationState.SPA_FALLBACK
    assert admin_outcome.confirmed is False


# 7. A protected 403 response is classified as protected, not exposed.
def test_protected_403_response_is_classified_protected_not_exposed():
    classification = classify_response("/.env", 403, {"Content-Type": "text/html"}, "Forbidden", None)
    outcome = validate_env_exposure(classification, "Forbidden")
    assert outcome.state == ValidationState.PROTECTED
    assert outcome.confirmed is False


# 8. A redirect to a login page is not automatically classified as an exposed admin panel.
def test_redirect_to_login_is_not_auto_confirmed_admin_panel():
    classification = classify_response(
        "/admin", 302, {"Content-Type": "text/html", "Location": "/login"}, "", None
    )
    outcome = validate_admin_panel(classification, "", baseline_title="OWASP Juice Shop")
    assert outcome.confirmed is False
    assert outcome.state == ValidationState.VALIDATED


def test_config_php_html_response_is_not_confirmed():
    body = "<html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root></body></html>"
    classification = classify_response("/config.php", 200, {"Content-Type": "text/html"}, body, _detector())
    outcome = validate_config_file(classification, body)
    assert outcome.confirmed is False


def test_config_php_real_source_is_confirmed():
    body = "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'root');\n"
    classification = classify_response("/wp-config.php", 200, {"Content-Type": "text/plain"}, body, _detector())
    outcome = validate_config_file(classification, body)
    assert outcome.confirmed is True
