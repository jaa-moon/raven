"""
validation/checks_static.py
---------------------------
Source-tree validators. Each re-reads the cited file through the gateway
(`file_inspection`) and re-derives the verdict; nothing is trusted from the
agent's claim.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from core.models import Confidence, Evidence, Finding, FindingStatus
from validation.evidence import file_evidence
from validation.outcome import conclude

_PLACEHOLDER = re.compile(
    r"(?i)(change[_-]?me|example|your[_-]|<[^>]+>|\$\{|xxx+|dummy|placeholder|"
    r"os\.environ|getenv|process\.env|\bnone\b|\bnull\b|todo)")
_TESTY = re.compile(r"(?i)(^|/)(tests?|__tests__|fixtures?|mocks?|examples?|docs?)(/|$)|\.(test|spec)\.")
# Patterns that are misconfigurations by themselves; everything else needs data-flow proof.
_INTRINSIC_RULES = {"debug-enabled", "tls-verify-off", "deser-yaml"}


class StaticChecks:
    async def _read(self, f: Finding, context: int = 0) -> Optional[List[Dict[str, Any]]]:
        sig = f.signal
        path = os.path.join(sig["root"], sig["file"])
        line = int(sig.get("line", 1))
        res = await self.ctx.call(
            "file_inspection",
            {"path": path, "start": max(line - context, 1), "end": line + context},
            f"Re-read {sig['file']}:{line}",
        )
        if not res.ok or not res.data.get("exists"):
            return None
        return res.data["lines"]

    async def _v_secret_in_file(self, f: Finding) -> Finding:  # type: ignore[misc]
        from tools.secret_scanner import _FORMAT_PATTERNS, _VAR_PATTERNS
        lines = await self._read(f)
        if not lines:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "The cited location could not be re-read.", "secret_in_file")
        text = lines[0]["text"]
        hit = None
        for name, pat in {**_FORMAT_PATTERNS, **_VAR_PATTERNS}.items():
            m = re.search(pat, text, re.I)
            if m:
                hit = (name, m.group(1) if m.lastindex else m.group(0))
                break
        ev = [file_evidence(f.signal["file"], lines, "Cited line re-read; value redacted.")]
        if hit is None:
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "No secret pattern matches the cited line on re-read.", "secret_in_file", ev)
        if _PLACEHOLDER.search(text) or _PLACEHOLDER.search(hit[1]):
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "Value is a placeholder or an environment reference, not a literal secret.",
                            "secret_in_file", ev)
        if _TESTY.search(f.signal["file"]):
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Pattern reproduced but the file looks like test/example material.",
                            "secret_in_file", ev)
        return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                        f"Literal {hit[0]} re-observed at the cited location.", "secret_in_file", ev)

    async def _v_code_pattern(self, f: Finding) -> Finding:  # type: ignore[misc]
        from tools.code_scanner import _COMPILED
        rule = f.signal["rule"]
        lines = await self._read(f)
        if not lines or rule not in _COMPILED:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "The cited location could not be re-read.", "code_pattern")
        ev = [file_evidence(f.signal["file"], lines, f"Rule '{rule}' re-checked against the cited line.")]
        if not _COMPILED[rule][0].search(lines[0]["text"]):
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "The pattern no longer matches at the cited line.", "code_pattern", ev)
        if _TESTY.search(f.signal["file"]):
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Pattern reproduced in test/example code.", "code_pattern", ev)
        if rule in _INTRINSIC_RULES:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "Insecure setting re-observed at the cited location.", "code_pattern", ev)
        return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.MEDIUM,
                        "Unsafe construct re-observed, but reachability from untrusted input was not "
                        "established; manual data-flow review required.", "code_pattern", ev)

    async def _v_config_setting(self, f: Finding) -> Finding:  # type: ignore[misc]
        lines = await self._read(f)
        if not lines:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "The cited location could not be re-read.", "config_setting")
        ev = [file_evidence(f.signal["file"], lines, "Cited configuration line re-read.")]
        needle = str(f.signal.get("line_content", "")).strip()
        if needle and needle[:60] in lines[0]["text"]:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "Insecure configuration re-observed at the cited line.", "config_setting", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        "The cited configuration line changed or is not present.", "config_setting", ev)

    async def _v_vulnerable_dependency(self, f: Finding) -> Finding:  # type: ignore[misc]
        from tools.advisories import _KNOWN_VULNS, _parse_version
        sig = f.signal
        res = await self.ctx.call(
            "file_inspection", {"path": os.path.join(sig["root"], sig["manifest"])},
            f"Re-read manifest {sig['manifest']}")
        if not res.ok or not res.data.get("exists"):
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Manifest could not be re-read.", "vulnerable_dependency")
        name, version = sig["package"].lower(), sig["version"]
        declared = [ln for ln in res.data["lines"] if name in ln["text"].lower() and version in ln["text"]]
        ev = [file_evidence(sig["manifest"], declared or res.data["lines"][:1], "Declared dependency re-read.")]
        advisories = [a for a in _KNOWN_VULNS.get(name, [])
                      if _parse_version(version) < _parse_version(a.get("max_version", "0"))]
        if not declared or not advisories:
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "Declared version is not affected on re-check.", "vulnerable_dependency", ev)
        return conclude(f, FindingStatus.CONFIRMED, Confidence.MEDIUM,
                        f"{name}=={version} is declared and predates the fix ({sig['fixed_in']}); "
                        "whether the vulnerable code path is reachable was not tested.",
                        "vulnerable_dependency", ev)

    async def _v_file_permission(self, f: Finding) -> Finding:  # type: ignore[misc]
        path, issue = f.signal["path"], f.signal.get("issue", "")
        res = await self.ctx.call("permission_audit", {"path": path}, f"Re-audit permissions of {path}")
        if not res.ok:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Permissions could not be re-audited.", "file_permission")
        same = [i for i in res.data.get("issues", []) if i.get("file") == path and i.get("issue") == issue]
        ev = [Evidence(kind="tool_output", source_tool="permission_scan",
                       summary=f"Permission re-audit of {os.path.basename(path)}", data={"matches": same[:3]})]
        if same:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "The same permission issue was re-observed.", "file_permission", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        "The permission issue is not present on re-audit.", "file_permission", ev)
