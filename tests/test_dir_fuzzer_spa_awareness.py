"""
tests/test_dir_fuzzer_spa_awareness.py
----------------------------------------
Regression test: DirFuzzer must not report SPA-fallback responses as
discovered routes, but must still report genuinely distinct responses.
"""

from tools.dir_fuzzer import DirFuzzer

_BASELINE = {
    "status": 200,
    "content_type": "text/html",
    "normalized_body": "<html><head><title>App</title></head><body><div id='root'></div></body></html>",
}


def test_is_spa_fallback_matches_dynamic_shell_variants():
    variant = "<html><head><title>App</title></head><body><div id='root'></div></body></html>"
    assert DirFuzzer._is_spa_fallback(200, "text/html", variant, _BASELINE) is True


def test_is_spa_fallback_rejects_distinct_content():
    distinct = "DATABASE_URL=postgres://x\nSECRET_KEY=y\n"
    assert DirFuzzer._is_spa_fallback(200, "text/plain", distinct, _BASELINE) is False


def test_is_spa_fallback_rejects_status_mismatch():
    assert DirFuzzer._is_spa_fallback(403, "text/html", "Forbidden", _BASELINE) is False
