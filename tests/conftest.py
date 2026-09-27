"""Shared fixtures: isolated RAVEN_HOME and local HTTP fixture servers."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, Iterable, Tuple, Union

import pytest

SPA_SHELL = (
    "<!doctype html><html><head><title>Fixture Shop</title>"
    "<script src=\"main.js\" type=\"module\"></script></head>"
    "<body><app-root></app-root></body></html>"
)
MAIN_JS = 'const a="/api/Items"; const b="/rest/basket"; export {a,b};'

# Headers as a plain dict (unique keys), or a list of (key, value) pairs when a
# route needs to repeat a header name -- e.g. two independent Set-Cookie lines,
# which a dict cannot represent.
Headers = Union[Dict[str, str], Iterable[Tuple[str, str]]]
Route = Tuple[int, Headers, str]


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch the real ~/.raven (state, learned lessons)."""
    monkeypatch.setenv("RAVEN_HOME", str(tmp_path / "raven_home"))
    return tmp_path / "raven_home"


class _Server:
    def __init__(self, routes: Callable[[str, Dict[str, str]], Route]) -> None:
        outer = routes

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                status, headers, body = outer(self.path, dict(self.headers))
                data = body.encode()
                self.send_response(status)
                items = headers.items() if isinstance(headers, dict) else headers
                for k, v in items:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_HEAD = do_GET  # noqa: N815
            # Route POST through the same handler: every fixture route function only
            # inspects path/query and ignores method, and leaving POST undefined makes
            # BaseHTTPRequestHandler's default 501 handling method-dependent in ways
            # that are not deterministic across requests (breaking response-jitter
            # comparisons for body-location injection probes).
            do_POST = do_GET  # noqa: N815

            def log_message(self, *a):  # silence
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _spa_routes(path: str, headers: Dict[str, str]) -> Route:
    """Juice-Shop-style: every unknown route returns the SPA shell with HTTP 200."""
    p = path.split("?")[0]
    html = {"content-type": "text/html; charset=utf-8"}
    if p == "/main.js":
        return 200, {"content-type": "application/javascript"}, MAIN_JS
    if p == "/robots.txt":
        return 200, {"content-type": "text/plain"}, "User-agent: *\nDisallow: /internal-api\n"
    if p == "/api/Items":
        return 200, {"content-type": "application/json"}, json.dumps([{"id": 1}])
    if p == "/internal-api":
        return 200, {"content-type": "application/json"}, json.dumps({"ok": True})
    return 200, html, SPA_SHELL


def _leaky_routes(path: str, headers: Dict[str, str]) -> Route:
    """A conventional server with a genuinely exposed .env and permissive CORS."""
    p = path.split("?")[0]
    if p == "/":
        return 200, {"content-type": "text/html", "access-control-allow-origin": "*"}, "<html><title>Home</title></html>"
    if p == "/.env":
        return 200, {"content-type": "text/plain"}, "DATABASE_URL=postgres://app:hunter2@db/app\nSECRET_KEY=topsecretvalue\n"
    if p == "/.git/HEAD":
        return 403, {"content-type": "text/html"}, "Forbidden"
    return 404, {"content-type": "text/html"}, "Not Found"


@pytest.fixture
def spa_server():
    s = _Server(_spa_routes)
    yield s
    s.close()


@pytest.fixture
def leaky_server():
    s = _Server(_leaky_routes)
    yield s
    s.close()


def _admin_leaky_routes(path: str, headers: Dict[str, str]) -> Route:
    """A server with genuine admin-panel, actuator, and config-file exposures at
    one path per group, and 404s for every sibling path in the same probe group --
    proves confirmation is evidence-based, not merely 'the path name looks sensitive'."""
    p = path.split("?")[0]
    if p == "/":
        return 200, {"content-type": "text/html"}, "<html><title>Corp Portal</title><body>Welcome</body></html>"
    if p == "/admin":
        return 200, {"content-type": "text/html"}, "<html><title>Admin Login</title><body><h1>Admin Panel Login</h1></body></html>"
    if p == "/actuator/health":
        return 200, {"content-type": "application/json"}, '{"status":"UP","components":{"db":{"status":"UP"}}}'
    if p == "/wp-config.php":
        return 200, {"content-type": "text/plain"}, "<?php\ndefine('DB_NAME', 'prod');\ndefine('DB_USER', 'root');\n"
    return 404, {"content-type": "text/html"}, "Not Found"


@pytest.fixture
def admin_leaky_server():
    s = _Server(_admin_leaky_routes)
    yield s
    s.close()


def _vulnerable_routes(path: str, headers: Dict[str, str]) -> Route:
    """A deliberately, safely vulnerable fixture: a fake (in-memory, read-only) SQL search,
    a reflected-XSS item page, and an SSRF-prone fetch parameter -- all synthetic, no real DB."""
    import urllib.parse

    p, _, qs = path.partition("?")
    params = dict(urllib.parse.parse_qsl(qs))
    html = {"content-type": "text/html; charset=utf-8"}

    if p == "/":
        body = ("<html><body>"
                "<form method=\"GET\" action=\"/search\"><input name=\"q\"></form>"
                "<form method=\"GET\"><input name=\"token\"></form>"        # action-less: submits to /
                "<a href=\"/item?id=1\">item</a> <a href=\"/fetch?url=x\">fetch</a>"
                "<a href=\"/widgets/7\">widget</a>"
                "</body></html>")
        # Two independent Set-Cookie headers (a real app cookie plus a
        # third-party analytics cookie) -- a dict cannot represent repeated
        # header names, so this route uses the list-of-pairs form.
        headers = [("content-type", html["content-type"]),
                  ("set-cookie", "session=abc123; Path=/"),
                  ("set-cookie", "_ga=GA1.1.111; Path=/")]
        return 200, headers, body

    if p.startswith("/widgets/"):
        # A conventional (non-SPA) REST resource keyed by a numeric path id --
        # reflects it unescaped, same shape as /item but reachable only via a
        # path segment, never a query string.
        item_id = p.rsplit("/", 1)[-1]
        return 200, html, f"<html><body><h1>Widget {item_id}</h1></body></html>"

    if p == "/swagger.json":
        spec = {
            "swagger": "2.0", "basePath": "/rest",
            "paths": {
                "/products/{id}": {"get": {"parameters": [
                    {"name": "id", "in": "path", "type": "string"},
                    {"name": "verbose", "in": "query", "type": "string"},
                ]}},
                "/products/search": {"post": {"parameters": [
                    {"name": "body", "in": "body", "schema": {"properties": {
                        "query": {"type": "string"}, "category": {"type": "string"}}}},
                ]}},
            },
        }
        return 200, {"content-type": "application/json"}, json.dumps(spec)

    if p == "/rest/products/1":
        return 200, html, "<html><body>Product 1</body></html>"

    if p == "/search":
        q = params.get("q", "")
        if "'" in q and "OR '1'='1'" not in q and "AND '1'='2'" not in q:
            return 500, html, f"Internal Server Error: you have an error in your SQL syntax near '{q}'"
        if "AND '1'='2'" in q:
            return 200, html, "<ul class=\"results\"></ul>"
        return 200, html, "<ul class=\"results\"><li>Widget</li><li>Gadget</li><li>Gizmo</li></ul>"

    if p == "/item":
        item_id = params.get("id", "1")
        return 200, html, f"<html><body><h1>Item {item_id}</h1><p>A fine product.</p></body></html>"

    if p == "/comment":
        import html as html_mod
        text = params.get("text", "")
        return 200, html, f"<html><body><p>Comment: {html_mod.escape(text)}</p></body></html>"

    if p == "/greet":
        # Reflects into an HTML attribute but escapes the tag-opening '<' and '>'
        # (only). The marker is reflected, yet no metacharacter opens a tag: this
        # is reflection, not executable XSS, and must NOT be confirmed.
        name = params.get("name", "").replace("<", "&lt;").replace(">", "&gt;")
        return 200, html, f"<html><body><input type=\"text\" value=\"{name}\"></body></html>"

    if p == "/fetch":
        target = params.get("url", "")
        if target.startswith("http://127.0.0.1"):
            import urllib.request
            try:
                urllib.request.urlopen(target, timeout=2).read()
            except Exception:
                pass
            return 200, {"content-type": "text/plain"}, "fetched"
        return 400, {"content-type": "text/plain"}, "invalid url"

    return 404, html, "Not Found"


@pytest.fixture
def vulnerable_server():
    s = _Server(_vulnerable_routes)
    yield s
    s.close()
