"""
ci/diff_scanner.py
------------------
Incremental diff scanning for Raven Phase 7 CI/CD integration.

Determines which files have changed relative to the merge-base of the current
branch and the upstream base branch.  Works identically on Windows and Linux
runners, handles all known edge cases:

  * Detached HEAD (common in Actions ``actions/checkout`` without fetch-depth)
  * Missing upstream remote / branch (falls back to ``git diff --name-only HEAD~1``)
  * Windows path separator vs. POSIX separators from git output
  * Binary and vendor files that Raven cannot parse
  * Renamed / deleted files (should not be scanned)

Exit codes / exceptions: this module never sys.exit().  Callers receive an
empty list when no scannable changed files exist.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

#: Directories that Raven always skips (mirrors core/file_analyzer.py).
EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".env",
        "dist",
        "build",
        "vendor",
        ".tox",
        "coverage",
        ".mypy_cache",
        ".ruff_cache",
    }
)

#: Extensions that Raven can meaningfully analyse.
SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
        ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".rs",
        ".kt", ".swift", ".sh", ".yml", ".yaml", ".toml",
        ".json", ".tf", ".hcl", ".env",
    }
)


# ── Public helpers ────────────────────────────────────────────────────────────

def is_ci_environment() -> bool:
    """Return True when running inside a known CI system (GitHub Actions, etc.)."""
    return (
        os.getenv("CI", "").lower() in {"true", "1"}
        or os.getenv("GITHUB_ACTIONS", "").lower() == "true"
        or os.getenv("GITLAB_CI", "").lower() == "true"
        or os.getenv("CIRCLECI", "").lower() == "true"
    )


def get_base_branch() -> str:
    """Determine the base branch to diff against.

    Resolution order:
      1. ``RAVEN_BASE_BRANCH`` env var (explicit override)
      2. ``GITHUB_BASE_REF`` env var (set by GitHub Actions on PR events)
      3. Existence of ``origin/main``
      4. Existence of ``origin/master``
      5. Fall-through: ``HEAD~1`` (single-commit diff)
    """
    explicit = os.getenv("RAVEN_BASE_BRANCH")
    if explicit:
        return explicit

    github_base = os.getenv("GITHUB_BASE_REF")
    if github_base:
        return f"origin/{github_base}"

    # Check which canonical branch exists
    for candidate in ("origin/main", "origin/master"):
        try:
            result = _git(["rev-parse", "--verify", candidate], check=False)
            if result.returncode == 0:
                return candidate
        except OSError:
            pass

    return "HEAD~1"


def get_changed_files(
    base_branch: Optional[str] = None,
    repo_root: Optional[Path] = None,
) -> List[Path]:
    """Return absolute paths of source files changed vs *base_branch*.

    Args:
        base_branch: Branch/ref to diff against.  Auto-detected when None.
        repo_root:   Repository root directory.  CWD is used when None.

    Returns:
        List of absolute ``Path`` objects for each changed, scannable file
        that still exists on disk (deleted/renamed files are excluded).
        Empty list when git is unavailable or no files match.
    """
    base = base_branch or get_base_branch()
    cwd = repo_root or _find_repo_root()

    try:
        raw_names = _get_diff_names(base=base, cwd=cwd)
    except _GitError as exc:
        logger.warning("git diff failed (%s); returning empty file list.", exc)
        return []

    result: List[Path] = []
    for raw in raw_names:
        # git outputs POSIX slashes even on Windows — normalise with Path()
        rel = Path(raw.strip())
        abs_path = (cwd / rel).resolve()

        # Skip if file no longer exists (deleted/renamed away)
        if not abs_path.is_file():
            continue

        # Skip excluded directories — check every component of the path
        path_parts = {p for p in rel.parts}
        if path_parts & EXCLUDE_DIRS:
            continue

        # Skip non-scannable extensions
        if abs_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue

        result.append(abs_path)

    logger.debug("Diff vs %s: %d scannable changed file(s).", base, len(result))
    return result


# ── Internal helpers ──────────────────────────────────────────────────────────

class _GitError(RuntimeError):
    """Raised when a git subprocess call fails."""


def _git(
    args: List[str],
    cwd: Optional[Path] = None,
    check: bool = True,
) -> "subprocess.CompletedProcess[str]":
    """Run a ``git`` subprocess and return its ``CompletedProcess``."""
    cmd = ["git", *args]
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=check,
        )
    except FileNotFoundError:
        raise _GitError("git executable not found") from None
    except subprocess.CalledProcessError as exc:
        raise _GitError(f"git {' '.join(args)} exited {exc.returncode}: {exc.stderr}") from exc


def _find_repo_root() -> Path:
    """Return the repository root, or the current working directory as fallback."""
    try:
        result = _git(["rev-parse", "--show-toplevel"], check=True)
        return Path(result.stdout.strip())
    except _GitError:
        return Path.cwd()


def _get_diff_names(base: str, cwd: Path) -> List[str]:
    """Return raw filenames changed between *base* and HEAD.

    Tries three strategies in order to handle detached-HEAD and shallow clones:
      1. ``git diff --name-only --diff-filter=ACMR <base>...HEAD``
      2. ``git diff --name-only --diff-filter=ACMR <base>``
      3. ``git diff --name-only --diff-filter=ACMR HEAD~1``
    """
    strategies = [
        ["diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"],
        ["diff", "--name-only", "--diff-filter=ACMR", base],
        ["diff", "--name-only", "--diff-filter=ACMR", "HEAD~1"],
    ]
    last_exc: Optional[_GitError] = None
    for args in strategies:
        try:
            result = _git(args, cwd=cwd, check=True)
            lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
            return lines
        except _GitError as exc:
            last_exc = exc
            logger.debug("Strategy %s failed: %s", args, exc)

    raise _GitError(f"All git diff strategies failed. Last error: {last_exc}")
