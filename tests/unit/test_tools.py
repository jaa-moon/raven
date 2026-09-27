"""Built-in tools and adapters (used through the registry, never directly by agents)."""

import asyncio

import pytest

from tools.catalog import build_registry
from tools.code_scanner import scan as code_scan
from tools.dependency_audit import audit_repository, parse_package_json, parse_requirements
from tools.inventory import file_classify, repo_inventory
from tools.protocol_prober import ProtocolProber


def test_registry_exposes_capabilities_not_tool_names():
    reg = build_registry()
    caps = reg.capabilities(available_only=False)
    assert {"http_request", "network_discovery", "secret_detection", "dependency_audit",
            "static_code_analysis", "config_audit", "file_inspection"} <= caps
    tool = reg.providers("secret_detection")[0]
    assert tool.risk_level == "passive" and "secret_detection" in tool.capabilities and tool.input_schema["path"].required


def test_permission_audit_is_unavailable_off_posix():
    import os
    reg = build_registry()
    assert bool(reg.providers("permission_audit")) == (os.name == "posix")


def test_secret_scan_masks_values(tmp_path):
    (tmp_path / "a.py").write_text('DB_PASSWORD = "Xk29!fjs81"\n')
    from tools.catalog import _secret_scan
    out = _secret_scan(str(tmp_path))
    assert out["matches"][0]["file"] == "a.py" and out["matches"][0]["line"] == 1
    assert "Xk29" not in str(out)


def test_dependency_parsers_and_audit(tmp_path):
    assert parse_requirements("flask==2.0.1  # web\n-r other.txt\nrequests>=2.0\n") == [("flask", "2.0.1"), ("requests", "2.0")]
    assert parse_package_json('{"dependencies": {"express": "^4.17.1"}}') == [("express", "4.17.1")]
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\nflask-cors==3.0.0\n")
    out = audit_repository(str(tmp_path))
    assert any(v["package"] == "flask" and v["fixed_in"] for v in out["vulnerabilities"])
    assert not any(v["package"] == "flask-cors" for v in out["vulnerabilities"])   # no substring matches


def test_code_scanner_ignores_comments_and_reports_lines(tmp_path):
    (tmp_path / "x.py").write_text("# eval(x)\nresult = eval(user)\nimport os\nos.system('ls')\n")
    issues = code_scan(str(tmp_path))["issues"]
    assert {(i["rule"], i["line"]) for i in issues} == {("code-eval", 2), ("cmd-os-system", 4)}


def test_config_scanner_flags_debug_mode_and_ignores_comments_and_false_values(tmp_path):
    (tmp_path / ".env").write_text(
        "# DEBUG=True\n"          # comment: must be ignored
        "DEBUG=True\n"            # line 2: must be flagged (CONF-001)
        "DEBUG=False\n"           # line 3: must NOT be flagged (no "False" in the pattern's alternation)
    )
    from tools.config_scanner import ConfigScanner
    out = ConfigScanner(str(tmp_path)).scan()
    assert out["vulnerable"] is True
    hits = [i for i in out["issues"] if i["check_id"] == "CONF-001"]
    assert {(i["line"], i["file"]) for i in hits} == {(2, ".env")}
    assert out["issues_count"] == 1


def _fake_stat_result(mode):
    """A minimal os.stat_result carrying only a controlled st_mode. Windows synthesizes
    its own (non-POSIX) st_mode for real files -- e.g. every file reports S_IWOTH set,
    regardless of any ACL -- so tests must build the mode from scratch rather than
    starting from a real stat() result, or they would assert on Windows's synthesized
    bits instead of PermissionScanner's actual bit-flag detection logic."""
    import os as os_mod
    return os_mod.stat_result((mode, 1, 1, 1, 0, 0, 0, 0, 0, 0))


def test_permission_scanner_detects_suid_and_world_writable_files(tmp_path, monkeypatch):
    """PermissionScanner's SUID/world-writable checks are pure bit-flag logic over
    st_mode; the stat.S_ISUID/S_IWOTH constants exist on every platform (they are just
    octal numbers), so the detection logic itself is portably testable via a mocked
    stat() even though real SUID files can't be created on this (Windows) dev machine."""
    import stat as stat_mod
    from pathlib import Path

    from tools.permission_scanner import PermissionScanner

    (tmp_path / "suid_bin").write_text("x")
    (tmp_path / "world_writable.txt").write_text("x")
    (tmp_path / "ordinary.txt").write_text("x")

    real_stat = Path.stat
    modes = {
        "suid_bin": stat_mod.S_IFREG | stat_mod.S_ISUID | 0o755,
        "world_writable.txt": stat_mod.S_IFREG | 0o666,
        "ordinary.txt": stat_mod.S_IFREG | 0o644,
    }

    def fake_stat(self, *a, **kw):
        if self.name in modes:
            return _fake_stat_result(modes[self.name])
        return real_stat(self, *a, **kw)

    monkeypatch.setattr(Path, "stat", fake_stat)

    out = PermissionScanner(str(tmp_path)).scan()
    assert out["vulnerable"] is True and out["files_checked"] == 3

    suid_issues = [i for i in out["issues"] if i["check_id"] == "PERM-001"]
    assert len(suid_issues) == 1
    assert suid_issues[0]["file"].endswith("suid_bin") and suid_issues[0]["severity"] == "HIGH"

    writable_issues = [i for i in out["issues"] if i["check_id"] == "PERM-003"]
    assert len(writable_issues) == 1
    assert writable_issues[0]["file"].endswith("world_writable.txt") and writable_issues[0]["severity"] == "HIGH"

    # The ordinary file must not appear in either issue list (no false positives).
    flagged_files = {i["file"] for i in out["issues"]}
    assert not any(f.endswith("ordinary.txt") for f in flagged_files)


def test_permission_scanner_reports_no_issues_for_ordinary_permissions(tmp_path, monkeypatch):
    """Same mocked-stat technique as the positive-detection test above, for the reason
    explained there: Windows's real, synthesized st_mode already sets S_IWOTH on every
    file, so only a controlled POSIX mode can exercise the 'no false positives on
    ordinary permissions' guarantee this check is meant to provide."""
    import stat as stat_mod
    from pathlib import Path

    from tools.permission_scanner import PermissionScanner

    (tmp_path / "readme.txt").write_text("hello")
    (tmp_path / "app.py").write_text("x = 1")

    real_stat = Path.stat
    ordinary_names = {"readme.txt", "app.py"}

    def fake_stat(self, *a, **kw):
        if self.name in ordinary_names:
            return _fake_stat_result(stat_mod.S_IFREG | 0o644)
        return real_stat(self, *a, **kw)

    monkeypatch.setattr(Path, "stat", fake_stat)

    out = PermissionScanner(str(tmp_path)).scan()
    assert out["vulnerable"] is False
    assert out["issues"] == []
    assert out["files_checked"] == 2


def test_inventory_and_file_classification(tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.0.0"}}')
    inv = repo_inventory(str(tmp_path))
    assert inv["extensions"][".py"] == 1 and inv["manifests"] == ["package.json"] and "express" in inv["dependencies"]
    (tmp_path / "prog").write_bytes(b"\x7fELF\x02\x01\x01")
    assert file_classify(str(tmp_path / "prog"))["format"] == "ELF"
    assert file_classify(str(tmp_path / "app.py"))["is_binary"] is False


async def test_protocol_prober_detects_redis_on_a_nonstandard_port():
    async def handler(r, w):
        await r.read(32)
        w.write(b"+PONG\r\n")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        res = await ProtocolProber("127.0.0.1", port, timeout=2).probe("auto")
    finally:
        srv.close()
        await srv.wait_closed()
    assert res["detected"] and res["protocol"] == "redis" and res["auth_required"] is False


async def test_http_client_classifies_unreachable_targets():
    from raven_mcp.models import ToolError
    from tools.http_client import request
    with pytest.raises(ToolError) as e:
        await request("http://127.0.0.1:1/", timeout=1)
    assert e.value.status == "target_unreachable"
