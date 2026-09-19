"""The validator must re-derive verdicts from fresh observations; HTTP 200 alone proves nothing."""

from core.models import Finding, FindingStatus, ToolResult
from validation.evidence import redact_text
from validation.validator import FindingValidator

SHELL = "<html><head><title>Shop</title></head><body><app-root></app-root></body></html>"
HTML = {"content-type": "text/html"}


class FakeCtx:
    """Serves canned HTTP routes / file lines and records every gateway call."""

    def __init__(self, routes=None, files=None):
        self.routes = routes or {}
        self.files = files or {}
        self.calls = []

    def lookup(self, query, purpose):
        return []

    async def call(self, capability, arguments, purpose):
        self.calls.append((capability, arguments))
        if capability == "http_request":
            path = "/" + arguments["url"].split("/", 3)[3] if arguments["url"].count("/") > 2 else "/"
            status, headers, body = self.routes.get(path.split("?")[0], self.routes["*"])
            return ToolResult(status="ok", data={
                "status_code": status, "headers": {k.lower(): v for k, v in headers.items()},
                "body": body, "content_type": headers.get("content-type", ""),
                "set_cookies": [headers["set-cookie"]] if "set-cookie" in headers else []})
        if capability == "file_inspection":
            lines = self.files.get(arguments["path"])
            return ToolResult(status="ok", data={"exists": lines is not None,
                                                 "lines": [{"n": i + 1, "text": t} for i, t in enumerate(lines or [])]})
        return ToolResult(status="tool_unavailable")


def path_finding(url):
    return Finding(title="Possible exposure", signal={"validator": "http_path_exposure", "url": url})


async def test_spa_shell_on_env_path_is_rejected():
    v = FindingValidator(FakeCtx({"*": (200, HTML, SHELL)}))
    f = await v.validate(path_finding("http://h/.env"))
    assert f.status == FindingStatus.REJECTED
    assert any(e.kind == "baseline_comparison" for e in f.evidence)


async def test_real_env_file_is_confirmed_and_secrets_are_redacted():
    body = "DATABASE_URL=postgres://u:hunter2@h/d\nSECRET_KEY=topsecret\n"
    v = FindingValidator(FakeCtx({"*": (200, HTML, SHELL), "/.env": (200, {"content-type": "text/plain"}, body)}))
    f = await v.validate(path_finding("http://h/.env"))
    assert f.status == FindingStatus.CONFIRMED and f.confidence.value == "high"
    dumped = f.model_dump_json()
    assert "hunter2" not in dumped and "topsecret" not in dumped


async def test_protected_403_is_not_reported_as_exposed():
    v = FindingValidator(FakeCtx({"*": (200, HTML, SHELL), "/.git/HEAD": (403, HTML, "Forbidden")}))
    f = await v.validate(path_finding("http://h/.git/HEAD"))
    assert f.status == FindingStatus.REJECTED


async def test_real_git_head_is_confirmed():
    v = FindingValidator(FakeCtx({"*": (404, HTML, "nf"), "/.git/HEAD": (200, {"content-type": "text/plain"}, "ref: refs/heads/main\n")}))
    assert (await v.validate(path_finding("http://h/.git/HEAD"))).status == FindingStatus.CONFIRMED


async def test_missing_header_confirmed_only_if_absent_on_refetch():
    sig = {"validator": "missing_header", "url": "http://h/", "header": "x-content-type-options"}
    absent = FindingValidator(FakeCtx({"*": (200, HTML, SHELL)}))
    assert (await absent.validate(Finding(signal=dict(sig)))).status == FindingStatus.CONFIRMED
    present = FindingValidator(FakeCtx({"*": (200, {**HTML, "X-Content-Type-Options": "nosniff"}, SHELL)}))
    assert (await present.validate(Finding(signal=dict(sig)))).status == FindingStatus.REJECTED


async def test_frame_ancestors_csp_makes_missing_xfo_a_false_positive():
    v = FindingValidator(FakeCtx({"*": (200, {**HTML, "Content-Security-Policy": "frame-ancestors 'none'"}, SHELL)}))
    f = await v.validate(Finding(signal={"validator": "missing_header", "url": "http://h/", "header": "x-frame-options"}))
    assert f.status == FindingStatus.REJECTED


async def test_cookie_secure_flag_over_http_is_not_confirmed_alone():
    v = FindingValidator(FakeCtx({"*": (200, {**HTML, "set-cookie": "sid=1; HttpOnly; SameSite=Lax"}, SHELL)}))
    f = await v.validate(Finding(signal={"validator": "cookie_flags", "url": "http://h/", "cookie": "sid", "missing": ["secure"]}))
    assert f.status == FindingStatus.INCONCLUSIVE


async def test_placeholder_secret_is_rejected_real_secret_confirmed(tmp_path):
    root = str(tmp_path)
    import os
    real, fake = os.path.join(root, "a.py"), os.path.join(root, "b.py")
    ctx = FakeCtx(files={real: ['DB_PASSWORD = "Xk29!fjs81"'], fake: ['API_KEY = "your_api_key_here"']})
    v = FindingValidator(ctx)
    ok = await v.validate(Finding(signal={"validator": "secret_in_file", "root": root, "file": "a.py", "line": 1}))
    no = await v.validate(Finding(signal={"validator": "secret_in_file", "root": root, "file": "b.py", "line": 1}))
    assert ok.status == FindingStatus.CONFIRMED and "Xk29" not in ok.model_dump_json()
    assert no.status == FindingStatus.REJECTED


async def test_code_pattern_needs_dataflow_so_unsafe_call_is_only_inconclusive(tmp_path):
    import os
    p = os.path.join(str(tmp_path), "x.py")
    v = FindingValidator(FakeCtx(files={p: ["subprocess.run(cmd, shell=True)"]}))
    f = await v.validate(Finding(signal={"validator": "code_pattern", "root": str(tmp_path), "rule": "cmd-shell-true", "file": "x.py", "line": 1}))
    assert f.status == FindingStatus.INCONCLUSIVE and "data-flow" in f.validation_notes[0]


async def test_finding_with_unknown_signal_is_never_confirmed():
    f = await FindingValidator(FakeCtx({"*": (200, HTML, SHELL)})).validate(Finding(signal={"validator": "made-up"}))
    assert f.status == FindingStatus.INCONCLUSIVE


async def test_validator_crash_is_contained():
    class Broken(FakeCtx):
        async def call(self, *a, **k):
            raise RuntimeError("gateway down")

    f = await FindingValidator(Broken()).validate(path_finding("http://h/.env"))
    assert f.status == FindingStatus.INCONCLUSIVE


def test_redaction_masks_dotenv_urls_and_key_values():
    out = redact_text('DATABASE_URL=postgres://u:hunter2@h/d\nSECRET_KEY=abc\npassword: "s3cret"\nplain = text')
    assert "hunter2" not in out and "abc" not in out and "s3cret" not in out
    assert out.count("<REDACTED>") >= 3
