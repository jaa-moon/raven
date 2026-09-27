"""
The controlled probe primitives themselves: baseline establishment, controlled
input variation, differential response analysis, reflection/context
detection -- all against a deterministic local fixture, no external targets.
"""

from __future__ import annotations

from tools.injection_probe import sql_probe, ssrf_probe, xss_probe


async def test_sql_probe_establishes_baseline_and_detects_error_signature(vulnerable_server):
    data = await sql_probe(vulnerable_server.url + "/search", "q")
    tests = data["tests"]
    assert tests["baseline"]["sql_error_signature"] is False
    assert tests["baseline"]["status_code"] == 200
    assert tests["quote"]["sql_error_signature"] is True
    assert tests["quote"]["status_code"] == 500


async def test_sql_probe_boolean_differential_matches_baseline_vs_diverges(vulnerable_server):
    data = await sql_probe(vulnerable_server.url + "/search", "q")
    tests = data["tests"]
    assert tests["true"]["status_code"] == tests["baseline"]["status_code"]
    assert len(tests["true"]["body"]) > 0
    assert "<li>" not in tests["false"]["body"]                       # empty result set on the false branch


async def test_sql_probe_on_a_non_injectable_parameter_is_uninteresting(vulnerable_server):
    data = await sql_probe(vulnerable_server.url + "/item", "id")
    tests = data["tests"]
    assert not any(t.get("sql_error_signature") for t in tests.values() if isinstance(t, dict))
    # /item echoes the id verbatim (plain reflection, not SQL processing): every payload comes back
    # in the response unmodified, and none of them provoke an error status.
    for name, value in {"baseline": "raven1", "quote": "raven1'", "true": "raven1' OR '1'='1' -- ",
                        "false": "raven1' AND '1'='2' -- "}.items():
        assert tests[name]["status_code"] == 200
        assert value in tests[name]["body"]


async def test_xss_probe_detects_unescaped_reflection_in_html_body(vulnerable_server):
    data = await xss_probe(vulnerable_server.url + "/item", "id")
    assert data["marker_reflected"] is True
    assert data["escaped"] is False
    assert data["context"] == "html_body"


async def test_xss_probe_rejects_html_escaped_reflection_as_false_positive(vulnerable_server):
    data = await xss_probe(vulnerable_server.url + "/comment", "text")
    assert data["marker_reflected"] is True
    assert data["escaped"] is True
    assert data["raw_reflected"] is False


async def test_xss_probe_reports_absent_when_parameter_is_not_reflected(vulnerable_server):
    # /fetch only ever echoes a fixed "invalid url" message for a parameter named 'other';
    # unlike /search (which echoes 'q' into its SQL-error branch), nothing here reflects it.
    data = await xss_probe(vulnerable_server.url + "/fetch", "other")
    assert data["marker_reflected"] is False
    assert data["context"] == "absent"


async def test_xss_probe_treats_partial_escaping_as_non_executable(vulnerable_server):
    # /greet escapes the tag-opening '<'/'>' (only). The marker is reflected, but
    # no metacharacter opens a tag -> reflection, not executable XSS.
    data = await xss_probe(vulnerable_server.url + "/greet", "name")
    assert data["marker_reflected"] is True
    assert data["tag_breakout"] is False
    assert data["escaped"] is True


async def test_sql_probe_captures_two_baselines_for_jitter(vulnerable_server):
    data = await sql_probe(vulnerable_server.url + "/search", "q")
    assert "baseline" in data["tests"] and "baseline2" in data["tests"]


async def test_ssrf_probe_reports_mechanism_unavailable_when_listener_fails(vulnerable_server, monkeypatch):
    async def _boom(token):
        raise OSError("cannot bind loopback listener")
    monkeypatch.setattr("tools.injection_probe._run_canary", _boom)
    data = await ssrf_probe(vulnerable_server.url + "/fetch", "url", settle=0.1)
    assert data["callback_available"] is False
    assert data["callback_received"] is False


async def test_ssrf_probe_detects_controlled_callback(vulnerable_server):
    data = await ssrf_probe(vulnerable_server.url + "/fetch", "url", settle=0.3)
    assert data["application_accepted"] is True
    assert data["callback_received"] is True


async def test_ssrf_probe_rejects_when_application_never_fetches(vulnerable_server):
    data = await ssrf_probe(vulnerable_server.url + "/item", "id", settle=0.3)
    assert data["callback_received"] is False


async def test_ssrf_probe_rejects_when_application_rejects_the_url(vulnerable_server):
    data = await ssrf_probe(vulnerable_server.url + "/fetch", "url", settle=0.1)
    # /fetch only accepts loopback-looking URLs; a payload that IS loopback is accepted (tested above).
    # Confirm the honest negative path exists too, using the raw response for a non-loopback value.
    from tools.injection_probe import _fetch, _place
    req = _place(vulnerable_server.url + "/fetch", "GET", "url", "query", "http://example.invalid/x")
    resp = await _fetch(**req)
    assert resp["status_code"] == 400
