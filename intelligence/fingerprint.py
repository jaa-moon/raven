"""
intelligence/fingerprint.py
---------------------------
Pure functions that turn observed HTTP / repository facts into technology
names. No I/O, fully unit-testable.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

_SERVER = [("nginx", "nginx"), ("apache", "Apache"), ("iis", "IIS"), ("werkzeug", "Flask"),
           ("gunicorn", "Gunicorn"), ("cloudflare", "Cloudflare"), ("caddy", "Caddy"), ("kestrel", "ASP.NET")]
_POWERED = [("express", "Express"), ("php", "PHP"), ("asp.net", "ASP.NET"), ("next.js", "Next.js")]
_COOKIES = [("connect.sid", "Express"), ("jsessionid", "Java"), ("phpsessid", "PHP"),
            ("laravel_session", "Laravel"), ("_rails_session", "Rails"), ("csrftoken", "Django")]
_BODY = [
    (r"<app-root|ng-version=", "Angular"),
    (r"__NEXT_DATA__|/_next/", "Next.js"),
    (r"data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js|id=[\"']root[\"']", "React"),
    (r"data-v-[0-9a-f]{6,}|vue(?:\.runtime)?(?:\.min)?\.js", "Vue"),
    (r"/wp-content/|/wp-includes/", "WordPress"),
    (r"csrfmiddlewaretoken", "Django"),
    (r"jquery[.-][0-9]", "jQuery"),
    (r"bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap"),
]
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

# Controlled vocabulary: the only technology names an LLM may add to a profile.
KNOWN_TECHNOLOGIES = {t.lower(): t for t in [
    "Angular", "React", "Vue", "Next.js", "Nuxt", "Svelte", "jQuery", "Bootstrap", "Express", "Node.js", "Django",
    "Flask", "FastAPI", "Rails", "Ruby", "Laravel", "PHP", "WordPress", "Drupal", "ASP.NET", "Spring", "Java",
    "nginx", "Apache", "IIS", "Caddy", "Gunicorn", "GraphQL", "Cloudflare", "Python", "Go", "Tomcat"]}


def canonical_technology(name: str) -> str:
    """Canonical spelling if *name* is a known technology, else ''."""
    return KNOWN_TECHNOLOGIES.get(name.strip().lower(), "")


# runtime implied by a framework, so later planning can reason about it
IMPLIES = {"Express": "Node.js", "Next.js": "Node.js", "Flask": "Python", "Django": "Python",
           "Laravel": "PHP", "Rails": "Ruby"}


def detect_web_technologies(headers: Dict[str, str], body: str, set_cookies: Iterable[str] = ()) -> List[str]:
    found: List[str] = []

    def add(name: str) -> None:
        if name not in found:
            found.append(name)

    server = headers.get("server", "").lower()
    for needle, name in _SERVER:
        if needle in server:
            add(name)
    powered = headers.get("x-powered-by", "").lower()
    for needle, name in _POWERED:
        if needle in powered:
            add(name)
    cookie_names = " ".join(c.split("=", 1)[0].lower() for c in set_cookies)
    for needle, name in _COOKIES:
        if needle in cookie_names:
            add(name)
    for pattern, name in _BODY:
        if re.search(pattern, body[:200_000], re.I):
            add(name)
    m = _GENERATOR.search(body)
    if m:
        add(m.group(1).strip()[:40])
    for name in list(found):
        if name in IMPLIES:
            add(IMPLIES[name])
    return found


_LANG = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
         ".php": "PHP", ".rb": "Ruby", ".go": "Go", ".java": "Java", ".rs": "Rust", ".cs": "C#"}


def languages_from_extensions(counts: Dict[str, int]) -> List[str]:
    tally: Dict[str, int] = {}
    for ext, n in counts.items():
        lang = _LANG.get(ext.lower())
        if lang:
            tally[lang] = tally.get(lang, 0) + n
    return [k for k, _ in sorted(tally.items(), key=lambda kv: -kv[1])]


def frameworks_from_manifests(dep_names: Iterable[str]) -> List[str]:
    known = {"flask": "Flask", "django": "Django", "fastapi": "FastAPI", "express": "Express",
             "next": "Next.js", "react": "React", "vue": "Vue", "@angular/core": "Angular",
             "spring-boot": "Spring", "rails": "Rails"}
    out = []
    for dep in dep_names:
        name = known.get(dep.lower())
        if name and name not in out:
            out.append(name)
    return out
