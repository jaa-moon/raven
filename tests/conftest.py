"""Shared fixtures: isolated RAVEN_HOME and local HTTP fixture servers."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, Tuple

import pytest

SPA_SHELL = (
    "<!doctype html><html><head><title>Fixture Shop</title>"
    "<script src=\"main.js\" type=\"module\"></script></head>"
    "<body><app-root></app-root></body></html>"
)
MAIN_JS = 'const a="/api/Items"; const b="/rest/basket"; export {a,b};'

Route = Tuple[int, Dict[str, str], str]


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
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_HEAD = do_GET  # noqa: N815

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
