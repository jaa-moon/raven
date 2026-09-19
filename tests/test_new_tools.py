"""
tests/test_new_tools.py
-----------------------
Unit tests for Raven v3.0 newly introduced security tools.
"""

import asyncio
from tools.banner_grabber import BannerGrabber, grab
from tools.protocol_prober import ProtocolProber, probe
from tools.default_creds_tester import DefaultCredsTester, test_creds as _test_creds
from tools.process_prober import ProcessProber, probe as proc_probe
from tools.cli_fuzzer import CLIFuzzer, fuzz
from tools.config_scanner import ConfigScanner, scan as cfg_scan
from tools.permission_scanner import PermissionScanner, scan as perm_scan


def test_banner_grabber_timeout_handling():
    # Test connection to unreachable port fails safely without crashing
    res = asyncio.run(grab(host="127.0.0.1", port=65534, timeout=0.5))
    assert res["success"] is False
    assert res["port"] == 65534
    assert res["banner"] == ""


def test_protocol_prober_unknown_port():
    res = asyncio.run(probe(host="127.0.0.1", port=65534, protocol="auto", timeout=0.5))
    assert res.get("detected") is False


def test_default_creds_tester():
    res = asyncio.run(_test_creds(host="127.0.0.1", port=65534, service="http", timeout=0.5))
    assert res["credentials_tested"] > 0
    assert res["vulnerable"] is False


def test_process_prober_current_process():
    res = asyncio.run(proc_probe())
    assert res["found"] is True
    assert res["count"] >= 1
    p = res["processes"][0]
    assert p["pid"] > 0
    assert "environ_keys" in p


def test_cli_fuzzer_nonexistent_binary():
    res = asyncio.run(fuzz(binary_path="nonexistent_binary_xyz_123"))
    assert "error" in res
    assert res["tests_run"] == 0


def test_config_scanner_self_audit():
    res = asyncio.run(cfg_scan("."))
    assert "files_scanned" in res
    assert "issues_count" in res
    assert isinstance(res["issues"], list)


def test_permission_scanner_self_audit():
    res = asyncio.run(perm_scan("."))
    assert "files_checked" in res
    assert res["files_checked"] > 0
    assert "issues_count" in res
