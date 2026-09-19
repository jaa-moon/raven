"""
tests/test_spa_fallback_detector.py
------------------------------------
Unit tests for web.spa_fallback_detector.SPAFallbackDetector.
"""

from web.spa_fallback_detector import SPAFallbackDetector

JUICE_SHOP_SHELL = """<!doctype html><html><head>
<title>OWASP Juice Shop</title>
<link rel="stylesheet" href="/styles/main.3f8a9c2e.css">
</head><body>
<app-root></app-root>
<script src="/runtime.a1b2c3d4.js"></script>
<script src="/main.9f8e7d6c.js"></script>
<meta name="csrf-token" content="a9f8e7d6c5b4a3f2e1d0">
</body></html>"""


def _make_fetcher(status=200, headers=None, body=JUICE_SHOP_SHELL):
    headers = headers if headers is not None else {"Content-Type": "text/html; charset=utf-8"}

    def fetcher(path):
        return status, headers, body

    return fetcher


def test_random_nonexistent_route_establishes_valid_baseline():
    detector = SPAFallbackDetector(fetcher=_make_fetcher())
    baseline = detector.establish_baseline()

    assert baseline.status_code == 200
    assert baseline.content_type.startswith("text/html")
    assert baseline.title == "OWASP Juice Shop"
    assert baseline.response_length == len(JUICE_SHOP_SHELL)
    assert baseline.body_hash


def test_identical_fallback_response_is_detected():
    detector = SPAFallbackDetector(fetcher=_make_fetcher())
    detector.establish_baseline()

    comparison = detector.compare(200, {"Content-Type": "text/html; charset=utf-8"}, JUICE_SHOP_SHELL)
    assert comparison.is_fallback is True
    assert comparison.similarity == 1.0


def test_dynamic_html_values_do_not_cause_false_differences():
    """Hashed asset names, csrf tokens, and timestamps differ per-request but
    the underlying document is the same SPA shell — must still match."""
    detector = SPAFallbackDetector(fetcher=_make_fetcher())
    detector.establish_baseline()

    candidate_body = """<!doctype html><html><head>
<title>OWASP Juice Shop</title>
<link rel="stylesheet" href="/styles/main.7d6c5b4a.css">
</head><body>
<app-root></app-root>
<script src="/runtime.11223344.js"></script>
<script src="/main.55667788.js"></script>
<meta name="csrf-token" content="00112233445566778899">
</body></html>"""

    comparison = detector.compare(200, {"Content-Type": "text/html; charset=utf-8"}, candidate_body)
    assert comparison.is_fallback is True
    assert comparison.similarity >= 0.92


def test_real_distinct_content_is_not_classified_as_fallback():
    detector = SPAFallbackDetector(fetcher=_make_fetcher())
    detector.establish_baseline()

    env_body = "DATABASE_URL=postgres://user:pass@localhost/db\nSECRET_KEY=supersecretvalue\n"
    comparison = detector.compare(200, {"Content-Type": "text/plain"}, env_body)
    assert comparison.is_fallback is False


def test_status_code_mismatch_is_not_fallback():
    detector = SPAFallbackDetector(fetcher=_make_fetcher(status=200))
    detector.establish_baseline()

    comparison = detector.compare(403, {"Content-Type": "text/html"}, "Forbidden")
    assert comparison.is_fallback is False
