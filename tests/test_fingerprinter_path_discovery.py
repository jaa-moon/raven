"""
tests/test_fingerprinter_path_discovery.py
--------------------------------------------
Integration-level regression tests: SiteFingerprinter must not report
sensitive-path exposures for an SPA (Juice-Shop-style) target, and must
still report a real exposure when the target actually has one.
"""

from dataclasses import dataclass, field

from web.crawler import CrawlResult
from web.fingerprinter import SiteFingerprinter

SPA_SHELL = (
    "<!doctype html><html><head><title>OWASP Juice Shop</title>"
    "<script src='/main.abc123ef.js'></script></head>"
    "<body><app-root></app-root></body></html>"
)


class _FakeResponse:
    def __init__(self, status_code, headers, text):
        self.status_code = status_code
        self.headers = headers
        self.text = text


class _FakeSession:
    """Stands in for requests.Session: every unknown path returns the SPA
    shell except the ones this test explicitly wires up as real resources."""

    def __init__(self, overrides: dict[str, tuple[int, dict, str]]):
        self.headers = {}
        self._overrides = overrides

    def get(self, url, timeout=None, verify=None, allow_redirects=None, **kwargs):
        from urllib.parse import urlparse
        path = urlparse(url).path
        if path in self._overrides:
            status, headers, body = self._overrides[path]
        else:
            status, headers, body = 200, {"Content-Type": "text/html"}, SPA_SHELL
        return _FakeResponse(status, headers, body)


def _make_crawl_result(base_url="http://localhost:3000"):
    return CrawlResult(base_url=base_url, pages=[], total_crawled=0)


def test_juice_shop_style_target_reports_no_confirmed_sensitive_paths():
    fingerprinter = SiteFingerprinter()
    fingerprinter._session = _FakeSession(overrides={})

    result = fingerprinter.fingerprint(_make_crawl_result())

    confirmed = [d for d in result.path_discoveries if d.validation_state == "confirmed"]
    assert confirmed == []
    # Every candidate should have been recognized as the SPA shell.
    fallback_count = sum(1 for d in result.path_discoveries if d.validation_state == "spa_fallback")
    assert fallback_count > 0
    assert result.interesting_paths == []


def test_target_with_real_env_exposure_is_confirmed():
    overrides = {
        "/.env": (200, {"Content-Type": "text/plain"}, "DATABASE_URL=postgres://x\nSECRET_KEY=y\n"),
    }
    fingerprinter = SiteFingerprinter()
    fingerprinter._session = _FakeSession(overrides=overrides)

    result = fingerprinter.fingerprint(_make_crawl_result())

    env_discovery = next(d for d in result.path_discoveries if d.path == "/.env")
    assert env_discovery.validation_state == "confirmed"
    assert any("/.env" in p for p in result.interesting_paths)

    # Other untouched sensitive paths must still be recognized as fallback.
    git_discovery = next(d for d in result.path_discoveries if d.path == "/.git/HEAD")
    assert git_discovery.validation_state == "spa_fallback"
