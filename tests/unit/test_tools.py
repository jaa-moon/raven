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
