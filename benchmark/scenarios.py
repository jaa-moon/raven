"""
benchmark/scenarios.py
----------------------
The controlled benchmark scenarios and their fixtures.

Every fixture is local, synthetic and authorized. The HTTP fixtures and binary
byte-builders are reused verbatim from the test suite (`tests/conftest.py`,
`tests/fixtures_binary.py`) so the benchmark exercises the exact same controlled
targets the integration tests already trust; only two small fixtures are added
here (a threaded redis-like TCP responder and a temp source/binary tree writer)
because the test-suite equivalents are async pytest fixtures that cannot be
driven from a standalone runner.

Each scenario's expected outcome is grounded in behaviour the integration suite
already asserts, not in optimistic guesses. A benchmark that codified wrong
expectations would be worse than none.
"""

from __future__ import annotations

import os
import shutil
import socketserver
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List

from core.budget import BudgetLimits
from core.models import CoverageStatus, FindingStatus

from benchmark.models import ExpectedFinding, Scenario
from tests.conftest import (
    _Server,
    _admin_leaky_routes,
    _graphql_no_introspection_routes,
    _graphql_routes,
    _leaky_routes,
    _spa_routes,
    _vulnerable_routes,
)
from tests.fixtures_binary import build_elf64

CONFIRMED = FindingStatus.CONFIRMED
INCONCLUSIVE = FindingStatus.INCONCLUSIVE

# Every local HTTP fixture serves responses without security headers, so a
# missing-header finding is a genuine, expected confirmation on each of them.
# Declaring it keeps the "unexpected confirmed" review list a tight regression
# signal instead of the same true finding repeated on every web scenario.
_MISSING_HEADERS = ExpectedFinding(CONFIRMED, validator="missing_header", label="missing-headers")

# Injection discovery + probing needs headroom the default "standard" budget
# does not give; this mirrors the GENEROUS limit the injection integration tests use.
GENEROUS = BudgetLimits(max_tool_calls=200, max_iterations=120, max_expensive_ops=30, max_llm_calls=50)

# The exact source tree the integration suite's `repo` fixture uses, so verdicts
# (real secret vs placeholder, shell=True inconclusive, DEBUG confirmed) are known.
_REPO_FILES: Dict[str, str] = {
    "requirements.txt": "flask==2.0.1\nrequests==2.31.0\n",
    "app.py": (
        "import subprocess, os\n"
        'DB_PASSWORD = "Xk29!fjs81"\n'
        'API_KEY = "your_api_key_here"\n'
        'token = os.environ["TOKEN"]\n'
        "def run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
        "DEBUG = True\n"
    ),
}
_CONFIG_REPO_FILES: Dict[str, str] = {
    "requirements.txt": "flask==2.0.1\n",
    ".env": "DATABASE_URL=postgres://app:hunter2@db/app\nDEBUG=True\n",
}


# ── fixture context managers (each yields the target string, then cleans up) ──────

@contextmanager
def _http(routes) -> Iterator[str]:
    s = _Server(routes)
    try:
        yield s.url
    finally:
        s.close()


class _RedisHandler(socketserver.BaseRequestHandler):
    """Minimal unauthenticated redis: answers PING with +PONG, matching the
    `test_network_target_finds_unauthenticated_redis` fixture's behaviour."""

    def handle(self):
        try:
            data = self.request.recv(64)
            self.request.sendall(b"+PONG\r\n" if b"PING" in data.upper() else b"-ERR unknown command\r\n")
        except OSError:
            pass


@contextmanager
def _redis() -> Iterator[str]:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _RedisHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


@contextmanager
def _source_tree(files: Dict[str, str]) -> Iterator[str]:
    d = Path(tempfile.mkdtemp(prefix="raven_bench_src_"))
    try:
        for rel, content in files.items():
            fp = d / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
        yield str(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@contextmanager
def _binary(data: bytes, name: str = "app.bin", suid: bool = False) -> Iterator[str]:
    d = Path(tempfile.mkdtemp(prefix="raven_bench_bin_"))
    try:
        p = d / name
        p.write_bytes(data)
        if suid and os.name == "posix":
            os.chmod(p, 0o4755)   # SUID + rwxr-xr-x; still world-readable so parsing works
        yield str(p)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ── setup factories (zero-arg, so scenarios stay declarative) ─────────────────────

def _leaky():        return _http(_leaky_routes)
def _spa():          return _http(_spa_routes)
def _admin():        return _http(_admin_leaky_routes)
def _vulnerable():   return _http(_vulnerable_routes)
def _graphql():      return _http(_graphql_routes)
def _graphql_noisp(): return _http(_graphql_no_introspection_routes)
def _repo():         return _source_tree(_REPO_FILES)
def _config_repo():  return _source_tree(_CONFIG_REPO_FILES)
# weak.elf keeps the builder's default embedded strings (an AWS-key-shaped and an
# internal-host-shaped string) so one scenario exercises hardening AND string
# inspection. The negative/permission ELFs pass extra_strings=() so their only
# possible finding is the one under test (crisp false-positive gate).
def _weak_elf():     return _binary(build_elf64(nx_disabled=True, relro="none", pie=False), "weak.elf")
def _hardened_elf(): return _binary(build_elf64(nx_disabled=False, relro="full", pie=True, extra_strings=()),
                                    "hardened.elf")
def _suid_elf():     return _binary(build_elf64(nx_disabled=False, relro="full", pie=True, extra_strings=()),
                                    "suid.elf", suid=True)


# ── the benchmark ─────────────────────────────────────────────────────────────────

SCENARIOS: List[Scenario] = [
    # 1. Web exposure — genuine exposed .env + permissive CORS are confirmed.
    Scenario(
        id="web-exposure-leaky", kind="positive", target_type="web_application",
        description="Conventional server with a real exposed /.env and wildcard CORS.",
        setup=_leaky,
        expected_capabilities=("http_request",),
        expected_tools=("http_request",),
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="http_path_exposure", location_contains="/.env",
                            label="env-exposure"),
            ExpectedFinding(CONFIRMED, validator="cors_reflection", label="cors"),
            ExpectedFinding(CONFIRMED, validator="missing_header", label="missing-headers"),
        ),
        expected_coverage={"Exposed paths & files": CoverageStatus.ASSESSED},
    ),

    # 2. Web exposure — SPA catch-all: sensitive paths return 200 but must NOT be confirmed.
    Scenario(
        id="web-exposure-spa-negative", kind="negative", target_type="web_application",
        description="SPA that answers 200 for every path; sensitive-file findings must be suppressed.",
        setup=_spa,
        expected_findings=(_MISSING_HEADERS,),
        forbidden_findings=(
            ExpectedFinding(CONFIRMED, validator="http_path_exposure", location_contains="/.env",
                            label="spa-env-fp"),
        ),
        expected_coverage={"REST API": CoverageStatus.ASSESSED},   # robots.txt + JS bundle reveal endpoints
        expected_overall="PARTIAL",
    ),

    # 3. Web exposure — admin panel, actuator, and config file, each content-validated.
    Scenario(
        id="web-exposure-admin", kind="positive", target_type="web_application",
        description="Genuine /admin, /actuator/health and /wp-config.php exposures; 404 siblings must not confirm.",
        setup=_admin,
        expected_findings=(
            ExpectedFinding(CONFIRMED, category="AdminPanelExposed", label="admin"),
            ExpectedFinding(CONFIRMED, category="ActuatorExposure", label="actuator"),
            ExpectedFinding(CONFIRMED, category="SensitiveFileExposure", location_contains="wp-config",
                            label="wp-config"),
            _MISSING_HEADERS,
        ),
        expected_coverage={"Exposed paths & files": CoverageStatus.ASSESSED},
    ),

    # 4. Passive web-config finding AND the active-injection risk gate (low risk => no active tests).
    Scenario(
        id="web-passive-and-injection-gate", kind="partial", target_type="web_application",
        description="At default (low) risk: session-cookie flags are flagged, but active injection is gated off.",
        setup=_vulnerable, max_risk="low",
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="cookie_flags", label="cookie-flags"),
            ExpectedFinding(CONFIRMED, validator="http_path_exposure", location_contains="swagger",
                            label="swagger-spec"),
            _MISSING_HEADERS,
        ),
        forbidden_findings=(
            ExpectedFinding(CONFIRMED, validator="sql_injection", label="sqli-should-be-gated"),
            ExpectedFinding(CONFIRMED, validator="ssrf", label="ssrf-should-be-gated"),
        ),
        expected_coverage={"SQL Injection": CoverageStatus.NOT_ASSESSED},
    ),

    # 5. REST active injection — SQLi, reflected XSS and SSRF all confirmed at moderate risk.
    Scenario(
        id="rest-injection-moderate", kind="positive", target_type="web_application",
        description="Deliberately vulnerable REST endpoints; SQLi/XSS/SSRF confirmed via independent re-probe.",
        setup=_vulnerable, max_risk="moderate", limits=GENEROUS,
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="sql_injection", label="rest-sqli"),
            ExpectedFinding(CONFIRMED, validator="reflected_xss", label="rest-xss"),
            ExpectedFinding(CONFIRMED, validator="ssrf", label="rest-ssrf"),
            ExpectedFinding(CONFIRMED, validator="cookie_flags", label="cookie-flags"),
            ExpectedFinding(CONFIRMED, validator="http_path_exposure", location_contains="swagger",
                            label="swagger-spec"),
            _MISSING_HEADERS,
        ),
        expected_coverage={
            "SQL Injection": CoverageStatus.ASSESSED,
            "XSS": CoverageStatus.ASSESSED,
            "SSRF": CoverageStatus.ASSESSED,
        },
    ),

    # 6. GraphQL active injection — a real SQLi signal on a query scalar arg is confirmed.
    Scenario(
        id="graphql-sqli-moderate", kind="positive", target_type="web_application",
        description="Introspection-driven GraphQL query-argument SQLi confirmed; safe field not confirmed.",
        setup=_graphql, max_risk="moderate", limits=GENEROUS,
        expected_findings=(
            ExpectedFinding(CONFIRMED, category="SQLInjection", label="graphql-sqli"),
            ExpectedFinding(CONFIRMED, validator="http_path_exposure", location_contains="graphql",
                            label="introspection-enabled"),
            _MISSING_HEADERS,
        ),
        expected_coverage={"GraphQL": CoverageStatus.ASSESSED},
    ),

    # 7. GraphQL with introspection disabled — no input surface fabricated; recorded as a limitation.
    Scenario(
        id="graphql-no-introspection-negative", kind="negative", target_type="web_application",
        description="Introspection rejected; Raven must not invent a GraphQL input surface or SQLi finding.",
        setup=_graphql_noisp, max_risk="moderate", limits=GENEROUS,
        expected_findings=(_MISSING_HEADERS,),
        forbidden_findings=(
            ExpectedFinding(CONFIRMED, category="SQLInjection", label="graphql-fabricated-sqli"),
        ),
    ),

    # 8. Network service — an unauthenticated redis is identified and confirmed.
    Scenario(
        id="network-redis", kind="positive", target_type="network_service",
        description="Unauthenticated redis on a local port; ExposedService confirmed, HTTP not applicable.",
        setup=_redis,
        expected_capabilities=("network_discovery",),
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="open_service", label="redis"),
        ),
        expected_coverage={
            "Network services": CoverageStatus.ASSESSED,
            "HTTP": CoverageStatus.NOT_APPLICABLE,
        },
    ),

    # 9. Source repo — real secret + vulnerable dep + config confirmed; shell=True stays inconclusive.
    Scenario(
        id="source-vulns", kind="positive", target_type="source_repository",
        description="Hardcoded secret, vulnerable dependency and DEBUG=True confirmed; shell=True inconclusive.",
        setup=_repo,
        expected_capabilities=("secret_detection", "dependency_audit", "static_code_analysis"),
        expected_tools=("secret_detection", "dependency_audit"),
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="secret_in_file", location_contains="app.py:2",
                            label="real-secret"),
            ExpectedFinding(CONFIRMED, validator="vulnerable_dependency", label="flask-dep"),
            ExpectedFinding(CONFIRMED, validator="code_pattern", location_contains="app.py:7",
                            label="debug-enabled"),
            ExpectedFinding(INCONCLUSIVE, validator="code_pattern", location_contains="app.py:6",
                            label="shell-true-inconclusive"),
        ),
        expected_coverage={
            "Secrets": CoverageStatus.ASSESSED,
            "Dependencies": CoverageStatus.ASSESSED,
            "Source code": CoverageStatus.ASSESSED,
            "HTTP": CoverageStatus.NOT_APPLICABLE,
        },
    ),

    # 10. Source config — an insecure .env setting is confirmed on independent re-read.
    Scenario(
        id="source-config", kind="positive", target_type="source_repository",
        description="A .env with DEBUG=True; SecurityMisconfiguration confirmed, Configuration assessed.",
        setup=_config_repo,
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="config_setting", label="debug-config"),
            # requirements.txt pins flask==2.0.1, so the dependency audit correctly fires too.
            ExpectedFinding(CONFIRMED, validator="vulnerable_dependency", label="flask-dep"),
        ),
        expected_coverage={"Configuration": CoverageStatus.ASSESSED},
    ),

    # 11. Static binary — a weakly-hardened ELF: missing mitigations confirmed.
    Scenario(
        id="binary-hardening", kind="positive", target_type="binary",
        description="ELF with NX off, no RELRO, no PIE; hardening gaps confirmed via re-parse.",
        setup=_weak_elf,
        expected_capabilities=("binary_hardening", "binary_strings"),
        expected_tools=("binary_hardening",),
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="binary_hardening_missing", label="hardening-gap"),
            ExpectedFinding(CONFIRMED, validator="binary_suspicious_string", label="embedded-secret"),
        ),
        expected_coverage={
            "Binary analysis": CoverageStatus.ASSESSED,
            "Process & CLI": CoverageStatus.NOT_ASSESSED,
        },
    ),

    # 12. Static binary (negative) — a fully-hardened ELF: no hardening gap may be confirmed.
    Scenario(
        id="binary-hardened-negative", kind="negative", target_type="binary",
        description="ELF with NX on, full RELRO and PIE; no missing-hardening finding may be confirmed.",
        setup=_hardened_elf,
        forbidden_findings=(
            ExpectedFinding(CONFIRMED, validator="binary_hardening_missing", label="false-hardening-gap"),
            ExpectedFinding(CONFIRMED, validator="binary_suspicious_string", label="false-string"),
        ),
        expected_coverage={"Binary analysis": CoverageStatus.ASSESSED},
    ),

    # 13. Binary file permissions (POSIX-only) — a SUID executable is flagged and confirmed.
    Scenario(
        id="binary-suid-perms", kind="positive", target_type="binary",
        description="A SUID ELF; file-permission finding confirmed. POSIX-only (skipped elsewhere).",
        setup=_suid_elf, posix_only=True,
        expected_capabilities=("permission_audit",),
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="file_permission", label="suid"),
        ),
        expected_coverage={"File permissions": CoverageStatus.ASSESSED},
    ),
]


def by_id(scenario_id: str) -> Scenario:
    for s in SCENARIOS:
        if s.id == scenario_id:
            return s
    raise KeyError(scenario_id)
