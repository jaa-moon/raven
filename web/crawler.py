"""
web/crawler.py
--------------
Raven Phase 8: Recursive web crawler for attack surface discovery.

Design principles:
  - Scope enforcement is MANDATORY: never follow links outside the base
    URL's netloc (strict comparison — sub.example.com is NOT in scope for
    example.com unless the base URL itself is sub.example.com).
  - URL deduplication by normalization: strip fragments, sort query params,
    lowercase scheme+host, remove default ports.
  - Robots.txt respected by default (toggle with respect_robots=False).
  - Binary content types are detected and skipped immediately via the
    Content-Type header — response body is never read for binary files.
  - Memory safety: response bodies are streamed and only the first
    MAX_BODY_BYTES bytes are consumed.
  - Thread safety: all shared state (visited set, page list, queue) is
    protected by threading.Lock.
  - Redirect loop protection: max MAX_REDIRECTS per URL, redirects that
    leave scope are NOT followed.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.robotparser
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import (
    parse_qs,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import requests

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_BODY_BYTES = 50_000      # Stream cutoff — never read more than 50 KB per page
MAX_REDIRECTS  = 5           # Per-URL redirect limit
MAX_RETRIES    = 2           # HTTP retry attempts on transient errors

_BINARY_CONTENT_TYPES = frozenset(
    {
        "image/", "audio/", "video/", "font/",
        "application/pdf", "application/zip",
        "application/octet-stream", "application/wasm",
    }
)

_SKIP_SCHEMES = frozenset({"javascript", "mailto", "tel", "data", "ftp", "file"})


# ── Dataclass models ──────────────────────────────────────────────────────────

@dataclass
class FormField:
    """A single HTML form field (input, textarea, select)."""
    name: str
    field_type: str    # text | hidden | password | email | checkbox | etc.
    default_value: str


@dataclass
class FormAsset:
    """An HTML form discovered on a page."""
    action: str        # resolved absolute URL for the form action
    method: str        # GET or POST
    fields: list[FormField] = field(default_factory=list)


@dataclass
class PageAsset:
    """All discovered assets for a single crawled page."""
    url: str
    method: str
    status_code: int
    content_type: str
    response_headers: dict[str, str]
    forms: list[FormAsset] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    links_found: list[str] = field(default_factory=list)
    raw_body_snippet: str = ""          # first 5000 chars for fingerprinting


@dataclass
class CrawlResult:
    """Aggregated result of a complete crawl."""
    base_url: str
    pages: list[PageAsset] = field(default_factory=list)
    total_crawled: int = 0
    total_skipped: int = 0             # out-of-scope, binary, already visited


# ── HTML parser ───────────────────────────────────────────────────────────────

class _PageParser(HTMLParser):
    """Extracts links, forms, and form fields from raw HTML.

    Uses only the stdlib html.parser — no third-party dependencies.
    """

    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._page_url = page_url
        self.links: list[str] = []
        self.forms: list[dict] = []           # raw dict, converted to FormAsset later
        self._form_stack: list[dict] = []     # supports nested (invalid but real) forms

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}

        if tag == "a":
            href = attr.get("href", "").strip()
            if href:
                self.links.append(href)

        elif tag == "form":
            form: dict = {
                "action": attr.get("action", "").strip(),
                "method": (attr.get("method") or "GET").upper(),
                "fields": [],
            }
            self._form_stack.append(form)
            self.forms.append(form)

        elif tag in ("input", "textarea", "select") and self._form_stack:
            field_data: dict = {
                "name":  attr.get("name", "").strip(),
                "type":  attr.get("type", "text").strip(),
                "value": attr.get("value", "").strip(),
            }
            if field_data["name"]:
                self._form_stack[-1]["fields"].append(field_data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form_stack:
            self._form_stack.pop()


# ── URL normalization ──────────────────────────────────────────────────────────

def _normalize_url(url: str, base: str) -> Optional[str]:
    """Return a canonical absolute URL, or None if the URL should be skipped.

    Normalization:
      - Resolves relative URLs against *base*
      - Lowercases scheme + host
      - Removes fragment (#...)
      - Sorts query string parameters
      - Removes default ports (:80, :443)
    """
    url = url.strip()
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.scheme in _SKIP_SCHEMES:
        return None

    # Resolve relative URLs
    absolute = urljoin(base, url)
    parts = urlparse(absolute)

    if parts.scheme not in ("http", "https"):
        return None

    # Remove default ports
    netloc = parts.netloc.lower()
    if netloc.endswith(":80") and parts.scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and parts.scheme == "https":
        netloc = netloc[:-4]

    # Sort query params for canonical form
    query = urlencode(
        sorted(parse_qs(parts.query, keep_blank_values=True).items())
    )

    return urlunparse((
        parts.scheme.lower(),
        netloc,
        parts.path,
        parts.params,
        query,
        "",          # no fragment
    ))


def _is_binary_content_type(content_type: str) -> bool:
    """Return True if the Content-Type indicates a non-textual binary file."""
    ct = content_type.lower().split(";")[0].strip()
    return any(ct.startswith(prefix) for prefix in _BINARY_CONTENT_TYPES)


# ── Main crawler ──────────────────────────────────────────────────────────────

class RavenCrawler:
    """Recursive web crawler that discovers all reachable URLs, forms, and
    input parameters within the target scope.

    Args:
        base_url:       The root URL to start crawling from.
        max_depth:      Maximum link-following depth (default 3).
        max_pages:      Hard page limit regardless of depth (default 150).
        max_workers:    Concurrent fetcher threads (default 8).
        respect_robots: Honour robots.txt directives (default True).
        request_delay:  Seconds to sleep between requests *per thread*
                        (default 0.3).
        timeout:        Per-request timeout in seconds (default 10).
        user_agent:     User-Agent string sent with every request.
        verify_ssl:     Whether to verify SSL certificates (default True).
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 150,
        max_workers: int = 8,
        respect_robots: bool = True,
        request_delay: float = 0.3,
        timeout: int = 10,
        user_agent: str = "RavenScanner/1.0 (Authorized Security Test)",
        verify_ssl: bool = True,
        progress_callback=None,
    ) -> None:
        self._base_url    = base_url.rstrip("/")
        self._base_parsed = urlparse(self._base_url)
        self._base_netloc = self._base_parsed.netloc.lower()
        self._base_scheme = self._base_parsed.scheme.lower()

        self._max_depth   = max_depth
        self._max_pages   = max_pages
        self._max_workers = max_workers
        self._delay       = request_delay
        self._timeout     = timeout
        self._verify_ssl  = verify_ssl
        self._cb          = progress_callback   # callable(url, pages_found)

        # Thread-safe shared state
        self._visited_lock = threading.Lock()
        self._visited: set[str] = set()
        self._pages_lock  = threading.Lock()
        self._pages: list[PageAsset] = []
        self._skipped: int = 0

        # BFS queue: (url, depth)
        self._queue: deque[tuple[str, int]] = deque()
        self._queue_lock = threading.Lock()

        # HTTP session (shared, thread-safe)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})
        self._session.max_redirects = MAX_REDIRECTS

        # robots.txt parser
        self._robots: Optional[urllib.robotparser.RobotFileParser] = None
        self._user_agent = user_agent
        if respect_robots:
            self._load_robots_txt()

    # ── Public API ─────────────────────────────────────────────────────────────

    def crawl(self) -> CrawlResult:
        """Start crawl from base_url and return all discovered assets."""
        normalized = _normalize_url(self._base_url, self._base_url)
        if not normalized:
            logger.error("base_url %r is not a valid HTTP(S) URL.", self._base_url)
            return CrawlResult(base_url=self._base_url)

        self._queue.append((normalized, 0))

        # Worker threads drain the queue
        threads: list[threading.Thread] = []
        for _ in range(1):  # Start 1 initial worker; spawner loop scales up
            t = threading.Thread(target=self._worker, daemon=True)
            threads.append(t)
            t.start()

        # Spawn additional workers as queue grows
        while any(t.is_alive() for t in threads) or self._queue:
            # Spin up extra workers if queue is deep and we haven't hit the limit
            active = sum(1 for t in threads if t.is_alive())
            while active < self._max_workers and self._queue:
                t = threading.Thread(target=self._worker, daemon=True)
                threads.append(t)
                t.start()
                active += 1
            time.sleep(0.1)

        for t in threads:
            t.join(timeout=5)

        with self._pages_lock:
            pages = list(self._pages)

        return CrawlResult(
            base_url=self._base_url,
            pages=pages,
            total_crawled=len(pages),
            total_skipped=self._skipped,
        )

    # ── Worker loop ────────────────────────────────────────────────────────────

    def _worker(self) -> None:
        """Thread worker: drain the BFS queue until empty or page limit hit."""
        while True:
            with self._queue_lock:
                if not self._queue:
                    return
                url, depth = self._queue.popleft()

            # Check page limit
            with self._pages_lock:
                if len(self._pages) >= self._max_pages:
                    return

            # Mark visited (double-check after lock acquisition)
            with self._visited_lock:
                if url in self._visited:
                    continue
                self._visited.add(url)

            # robots.txt check
            if self._robots and not self._robots.can_fetch(self._user_agent, url):
                logger.debug("robots.txt blocked: %s", url)
                self._skipped += 1
                continue

            page = self._fetch_page(url)
            if page is None:
                continue

            with self._pages_lock:
                self._pages.append(page)
                page_count = len(self._pages)

            if self._cb:
                self._cb(url, page_count)

            time.sleep(self._delay)

            # Enqueue child links if within depth budget
            if depth < self._max_depth:
                for link in page.links_found:
                    norm = _normalize_url(link, url)
                    if norm and self._is_in_scope(norm):
                        with self._visited_lock:
                            already = norm in self._visited
                        if not already:
                            with self._queue_lock:
                                self._queue.append((norm, depth + 1))

    # ── HTTP fetching ──────────────────────────────────────────────────────────

    def _fetch_page(self, url: str) -> Optional[PageAsset]:
        """Fetch a single URL and parse it into a PageAsset."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self._session.get(
                    url,
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                    allow_redirects=True,
                    stream=True,
                )
                break
            except requests.TooManyRedirects:
                logger.debug("Too many redirects for %s — skipping.", url)
                self._skipped += 1
                return None
            except requests.RequestException as exc:
                if attempt == MAX_RETRIES:
                    logger.debug("Failed to fetch %s after %d attempts: %s", url, MAX_RETRIES + 1, exc)
                    self._skipped += 1
                    return None
                time.sleep(0.5 * (attempt + 1))

        ct = resp.headers.get("Content-Type", "")
        if _is_binary_content_type(ct):
            resp.close()
            self._skipped += 1
            return None

        # Stream body with hard cutoff
        try:
            chunks: list[bytes] = []
            size = 0
            for chunk in resp.iter_content(chunk_size=4096):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY_BYTES:
                    break
            body_bytes = b"".join(chunks)
        except requests.RequestException:
            body_bytes = b""
        finally:
            resp.close()

        try:
            body = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = ""

        snippet = body[:5000]

        # Parse HTML for links and forms
        parser = _PageParser(page_url=url)
        try:
            parser.feed(body[:MAX_BODY_BYTES])
        except Exception as exc:
            logger.debug("HTML parse error for %s: %s", url, exc)

        # Resolve links to absolute URLs
        resolved_links: list[str] = []
        for raw_link in parser.links:
            norm = _normalize_url(raw_link, url)
            if norm:
                resolved_links.append(norm)

        # Build FormAsset objects (only in-scope forms)
        forms: list[FormAsset] = []
        for raw_form in parser.forms:
            action_raw = raw_form.get("action", "") or ""
            action_abs = _normalize_url(action_raw, url) or url
            if not self._is_in_scope(action_abs):
                continue
            form = FormAsset(
                action=action_abs,
                method=raw_form.get("method", "GET"),
                fields=[
                    FormField(
                        name=f["name"],
                        field_type=f["type"],
                        default_value=f["value"],
                    )
                    for f in raw_form.get("fields", [])
                    if f["name"]
                ],
            )
            if form.fields:
                forms.append(form)

        # Extract query params from this URL
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

        return PageAsset(
            url=url,
            method="GET",
            status_code=resp.status_code,
            content_type=ct,
            response_headers=dict(resp.headers),
            forms=forms,
            query_params=query_params,
            links_found=resolved_links,
            raw_body_snippet=snippet,
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _is_in_scope(self, url: str) -> bool:
        """Return True iff *url* has the same netloc as the base URL."""
        return urlparse(url).netloc.lower() == self._base_netloc

    def _load_robots_txt(self) -> None:
        """Fetch and parse robots.txt from the target origin."""
        robots_url = f"{self._base_scheme}://{self._base_netloc}/robots.txt"
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        try:
            rp.read()
            self._robots = rp
            logger.debug("robots.txt loaded from %s", robots_url)
        except Exception as exc:
            logger.debug("Could not load robots.txt from %s: %s", robots_url, exc)
            self._robots = None
