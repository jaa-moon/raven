"""
ci/pr_reporter.py
-----------------
Posts an automated Raven scan summary as a GitHub Pull Request comment.

Design decisions:
  * Uses only the ``GITHUB_TOKEN`` environment variable — never reads API keys.
  * Uses ``urllib.request`` (stdlib) rather than ``requests``/``httpx`` so there
    is zero additional install burden in CI.
  * Truncates body > 65 000 chars to avoid GitHub's 65 536 comment length limit.
  * Is idempotent: if a previous Raven comment exists on the PR it is *updated*
    rather than creating a new one (identified by the ``<!-- raven-scan-report -->``
    sentinel comment).
  * Exits 0 even on failure — PR annotation is best-effort and must never block
    the CI pipeline.

Usage (called from the GitHub Actions step):

    python ci/pr_reporter.py --results raven-results.json

Required env vars:
  GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH (or PR_NUMBER)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_SENTINEL = "<!-- raven-scan-report -->"
_MAX_BODY = 65_000          # GitHub's practical comment size limit
_API_BASE = "https://api.github.com"
_SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🔵",
    "Info":     "⚪",
}


# ── Public entry point ────────────────────────────────────────────────────────

def post_pr_comment(results_path: str) -> None:
    """Read *results_path* and post (or update) a PR comment with the summary.

    Silently returns on any failure so the CI step always exits 0.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        logger.warning("GITHUB_TOKEN not set; skipping PR comment.")
        return

    repo = os.getenv("GITHUB_REPOSITORY")
    if not repo:
        logger.warning("GITHUB_REPOSITORY not set; skipping PR comment.")
        return

    pr_number = _get_pr_number()
    if pr_number is None:
        logger.warning("Could not determine PR number; skipping PR comment.")
        return

    results = _load_results(results_path)
    if results is None:
        return

    body = _build_comment_body(results)
    _upsert_comment(token=token, repo=repo, pr_number=pr_number, body=body)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_pr_number() -> Optional[int]:
    """Return the pull request number from environment variables."""
    # Explicit override
    explicit = os.getenv("PR_NUMBER")
    if explicit and explicit.isdigit():
        return int(explicit)

    # GitHub Actions: parse from event payload
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if event_path:
        try:
            event = json.loads(Path(event_path).read_text(encoding="utf-8"))
            pr = event.get("pull_request") or event.get("number")
            if isinstance(pr, dict):
                return pr.get("number")
            if isinstance(pr, int):
                return pr
        except Exception as exc:
            logger.debug("Could not parse event payload: %s", exc)

    return None


def _load_results(path: str) -> Optional[Dict[str, Any]]:
    """Load the JSON results file produced by ``raven scan --output-json``."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not read results file %r: %s", path, exc)
        return None


def _build_comment_body(results: Dict[str, Any]) -> str:
    """Render the PR comment markdown from the scan results payload."""
    total   = results.get("total_findings", 0)
    target  = results.get("target", "unknown")
    elapsed = results.get("elapsed_seconds", 0.0)
    model   = results.get("model", "—")
    fail_on = results.get("fail_on", "high")
    sev     = results.get("findings_by_severity", {})
    adv_cnt = results.get("adversarial_findings_count", 0)
    timestamp = results.get("timestamp", "—")

    pass_fail_icon = "✅" if total == 0 else (
        "🔴" if (sev.get("Critical", 0) or sev.get("High", 0)) else "🟡"
    )

    lines: List[str] = [
        _SENTINEL,
        "",
        f"## {pass_fail_icon} Raven Security Scan — PR Report",
        "",
        f"> Scanned: `{target}`  |  Model: `{model}`  |  "
        f"Fail threshold: `--fail-on {fail_on}`  |  Time: `{elapsed:.1f}s`",
        "",
        "### Findings Summary",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]

    for sev_name in ("Critical", "High", "Medium", "Low", "Info"):
        count = sev.get(sev_name, 0)
        emoji = _SEVERITY_EMOJI.get(sev_name, "")
        lines.append(f"| {emoji} {sev_name} | {count} |")

    lines += [
        "",
        f"**Total findings:** {total}",
    ]

    if adv_cnt:
        lines += [
            "",
            f"🔥 **Adversarial / red-team findings:** {adv_cnt}",
        ]

    # ── Top findings ──────────────────────────────────────────────────────────
    findings: List[Dict[str, Any]] = results.get("findings", [])
    if findings:
        lines += [
            "",
            "<details>",
            "<summary><strong>Top findings (click to expand)</strong></summary>",
            "",
        ]
        _SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        top = sorted(
            findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "Info"), 4)
        )[:15]

        for f in top:
            emoji  = _SEVERITY_EMOJI.get(f.get("severity", "Info"), "")
            sev_lbl = f.get("severity", "?")
            title  = f.get("title", "Untitled")
            file_  = f.get("file", "—")
            line_  = f.get("line_hint") or f.get("line") or "—"
            desc   = (f.get("description") or "")[:300].replace("\n", " ")

            lines += [
                f"#### {emoji} {sev_lbl} — {title}",
                f"**File:** `{file_}`  **Location:** {line_}",
                "",
                desc,
                "",
                "---",
                "",
            ]

        lines += ["</details>", ""]

    # ── Adversarial top findings ──────────────────────────────────────────────
    adv_findings: List[Dict[str, Any]] = results.get("adversarial_findings", [])
    if adv_findings:
        lines += [
            "<details>",
            "<summary><strong>🔥 Red-team findings (click to expand)</strong></summary>",
            "",
        ]
        _ADV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        top_adv = sorted(
            adv_findings,
            key=lambda f: _ADV_ORDER.get(str(f.get("attack_impact", "")).upper(), 4),
        )[:10]

        for af in top_adv:
            impact    = str(af.get("attack_impact", "—")).upper()
            title     = af.get("title", "Untitled")
            file_path = af.get("file_path", "—")
            narrative = (af.get("attacker_narrative") or "")[:300].replace("\n", " ")

            lines += [
                f"#### 🔥 {impact} — {title}",
                f"**File:** `{file_path}`",
                "",
                narrative,
                "",
                "---",
                "",
            ]

        lines += ["</details>", ""]

    lines += [
        f"*Generated at: {timestamp} by [Raven](https://github.com/aryan-raven/raven)*",
    ]

    body = "\n".join(lines)
    if len(body) > _MAX_BODY:
        truncation_notice = "\n\n*[Report truncated — view full results in the workflow artefact.]*"
        body = body[: _MAX_BODY - len(truncation_notice)] + truncation_notice

    return body


def _gh_request(
    method: str,
    url: str,
    token: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Make an authenticated GitHub API call and return the parsed JSON response."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "raven-ci/1.0",
    }
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        logger.warning("GitHub API %s %s → HTTP %s: %s", method, url, exc.code, exc.read())
        return None
    except Exception as exc:
        logger.warning("GitHub API request failed: %s", exc)
        return None


def _upsert_comment(token: str, repo: str, pr_number: int, body: str) -> None:
    """Create or update the Raven sentinel comment on the PR."""
    list_url = f"{_API_BASE}/repos/{repo}/issues/{pr_number}/comments"

    # List existing comments — look for the sentinel
    existing = _gh_request("GET", list_url, token)
    if existing is None:
        # Fallback: just create a new comment
        logger.debug("Could not list comments; creating new comment.")
        _gh_request("POST", list_url, token, payload={"body": body})
        return

    existing_id: Optional[int] = None
    for comment in existing if isinstance(existing, list) else []:
        if _SENTINEL in comment.get("body", ""):
            existing_id = comment.get("id")
            break

    if existing_id:
        update_url = f"{_API_BASE}/repos/{repo}/issues/comments/{existing_id}"
        result = _gh_request("PATCH", update_url, token, payload={"body": body})
        if result:
            logger.info("Updated existing Raven comment (ID %s).", existing_id)
    else:
        result = _gh_request("POST", list_url, token, payload={"body": body})
        if result:
            logger.info("Created new Raven PR comment.")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Post a Raven scan summary as a GitHub PR comment."
    )
    parser.add_argument(
        "--results",
        required=True,
        help="Path to the raven-results.json file produced by raven scan --output-json.",
    )
    args = parser.parse_args()
    post_pr_comment(args.results)


if __name__ == "__main__":
    main()
