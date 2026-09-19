"""
tests/test_response_classifier.py
-----------------------------------
Unit tests for web.response_classifier.classify_response.
"""

from web.response_classifier import ResponseClass, classify_response
from web.spa_fallback_detector import SPAFallbackDetector

SPA_SHELL = "<html><head><title>App</title></head><body><div id='root'></div></body></html>"


def _detector_with_baseline(body=SPA_SHELL, status=200, content_type="text/html"):
    detector = SPAFallbackDetector(
        fetcher=lambda p: (status, {"Content-Type": content_type}, body)
    )
    detector.establish_baseline()
    return detector


def test_juice_shop_style_spa_fallback_is_not_confirmed():
    detector = _detector_with_baseline()
    result = classify_response(
        "/.env", 200, {"Content-Type": "text/html"}, SPA_SHELL, detector
    )
    assert result.classification == ResponseClass.SPA_FALLBACK


def test_generic_200_html_without_baseline_is_real_resource_pending_validation():
    """Without any baseline established, a 200 cannot be assumed SPA fallback,
    but it is also not automatically 'confirmed' anywhere downstream — this
    module only classifies, it never confirms."""
    result = classify_response("/some/page", 200, {"Content-Type": "text/html"}, "<html>hi</html>", None)
    assert result.classification == ResponseClass.REAL_RESOURCE


def test_protected_403_is_classified_as_protected_not_exposed():
    result = classify_response("/admin", 403, {"Content-Type": "text/html"}, "Forbidden", None)
    assert result.classification == ResponseClass.PROTECTED


def test_redirect_to_login_is_classified_as_redirect_not_admin_exposure():
    result = classify_response(
        "/admin", 302, {"Content-Type": "text/html", "Location": "/login"}, "", None
    )
    assert result.classification == ResponseClass.REDIRECT
    assert result.redirect_location == "/login"


def test_generic_404_is_classified_correctly():
    result = classify_response("/nope", 404, {}, "Not Found", None)
    assert result.classification == ResponseClass.GENERIC_404


def test_real_exposed_env_response_is_not_spa_fallback():
    detector = _detector_with_baseline()
    body = "DATABASE_URL=postgres://user:pass@host/db\nSECRET_KEY=abc123\n"
    result = classify_response("/.env", 200, {"Content-Type": "text/plain"}, body, detector)
    assert result.classification == ResponseClass.REAL_RESOURCE


def test_json_actuator_response_is_detected_as_json():
    detector = _detector_with_baseline()
    body = '{"status": "UP", "components": {}}'
    result = classify_response(
        "/actuator/health", 200, {"Content-Type": "application/json"}, body, detector
    )
    assert result.classification == ResponseClass.REAL_RESOURCE
    assert result.is_json is True
