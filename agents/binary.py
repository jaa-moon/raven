"""
agents/binary.py
-----------------
Static assessment of a single authorized local binary executable (ELF / PE /
Mach-O): container format and architecture identification, header-level
exploit-mitigation ("hardening") indicators, ELF imported-library
enumeration, and embedded printable-string inspection.

STATIC ONLY, deliberately, for this milestone: the target binary is never
executed, mapped, or sandboxed. Dynamic/execution-based analysis (the
"Process & CLI" coverage surface in core/coverage.py) is explicitly out of
scope here and remains NOT_ASSESSED -- no agent implements it yet.

Every capability call below can come back describing a genuine limitation
(unsupported format, PE imports/Mach-O not implemented, a truncated/corrupt
header) instead of a result; those are recorded as limitations and, when a
whole check could not run for this binary's format, the task is marked
`blocked` (not `done`) so coverage reflects it honestly rather than as a
silent "checked, nothing found".
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from agents.base import Agent, AgentContext, AgentResult
from core.models import Severity, TestTask
from core.profile import TargetProfile
from core.state import AssessmentState

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}

# Suspicious-string categories severe enough to treat as a likely hardcoded secret.
_STRING_HIGH = {"AWS Access Key", "JWT Token", "Private Key Header", "GitHub Token", "Slack Token",
                "Generic API Key Literal"}


class BinaryAssessmentAgent(Agent):
    name = "binary_assessment"
    description = ("Static analysis of a single binary executable: format/architecture identification, "
                   "header-level hardening indicators, imported-library enumeration, and embedded-string "
                   "inspection. Never executes the target binary.")
    capabilities = ["binary_format_id", "binary_hardening", "binary_imports", "binary_strings"]

    def applies(self, profile: TargetProfile) -> bool:
        return profile.target_type == "binary"

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        return [
            self.task("format", "binary_format_id", "Binary analysis",
                      "Identify binary container format and CPU architecture", priority=85,
                      rationale="Establish what the target actually is before checking anything else."),
            self.task("hardening", "binary_hardening", "Binary analysis",
                      "Check header-level exploit-mitigation (hardening) indicators", priority=75),
            self.task("imports", "binary_imports", "Binary analysis",
                      "Enumerate imported shared libraries", priority=60),
            self.task("strings", "binary_strings", "Binary analysis",
                      "Extract and inspect embedded printable strings", priority=50),
        ]

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        path = ctx.profile.attributes["root"]
        res = await ctx.call(task.capability, {"path": path}, task.title)
        if not res.ok:
            return AgentResult(success=False, blocked=res.status in ("out_of_scope", "tool_unavailable"),
                               error=res.error)
        step = task.key.split(".", 1)[1]
        return await getattr(self, f"_{step}")(ctx, path, res.data)

    # -- steps ------------------------------------------------------------------------

    async def _format(self, ctx: AgentContext, path: str, data: Dict[str, Any]) -> AgentResult:
        for lim in data.get("limitations", []):
            ctx.state.add_limitation(lim)
        if not data.get("is_binary", True):
            ctx.observe("binary.identify", "Binary analysis", "Target is not a recognized binary format.")
            return AgentResult(summary="not a recognized binary format")
        fmt = data.get("format", "unknown")
        if data.get("parsed") is False:
            ctx.observe("binary.identify", "Binary analysis",
                        f"{fmt}: header could not be parsed ({data.get('error', 'unknown error')}).")
            return AgentResult(summary=f"{fmt}: header parse failed")
        ctx.profile.attributes["binary_format"] = fmt
        ctx.profile.attributes["binary_arch"] = data.get("arch")
        summary = f"{fmt} {data.get('bits', '?')}-bit {data.get('endianness', '')} ({data.get('arch', 'unknown')})".strip()
        ctx.observe("binary.identify", "Binary analysis", summary, format=fmt, arch=data.get("arch"),
                    bits=data.get("bits"), endianness=data.get("endianness"))
        return AgentResult(summary=summary)

    async def _hardening(self, ctx: AgentContext, path: str, data: Dict[str, Any]) -> AgentResult:
        for lim in data.get("limitations", []):
            ctx.state.add_limitation(lim)
        if not data.get("supported", True):
            return AgentResult(success=False, blocked=True,
                               error="; ".join(data.get("limitations",
                                   ["Hardening check not supported for this format."])))
        if data.get("parsed") is False:
            return AgentResult(summary=f"header malformed; hardening indicators not determined "
                                       f"({data.get('error', '')})")
        hard = data.get("hardening", {})
        from tools.binary_scanner import missing_hardening_properties
        missing = missing_hardening_properties(hard, data.get("format", ""))
        n = 0
        for m in missing:
            f = ctx.candidate(
                title=f"Missing {m['label']} in {os.path.basename(path)}",
                category="BinaryHardeningGap", severity=_SEV.get(m["severity"], Severity.LOW),
                surface="Binary analysis", location=path, description=m["description"],
                impact="Reduces the cost of exploiting a memory-corruption vulnerability in this binary, "
                       "if one exists; this is not itself proof of an exploitable bug.",
                remediation=m["remediation"],
                signal={"validator": "binary_hardening_missing", "path": path, "property": m["property"]})
            n += bool(f)
        ctx.observe("binary.hardening", "Binary analysis", f"hardening indicators: {hard}; {n} gap(s) found.")
        return AgentResult(summary=f"{n} hardening gap(s)")

    async def _imports(self, ctx: AgentContext, path: str, data: Dict[str, Any]) -> AgentResult:
        for lim in data.get("limitations", []):
            ctx.state.add_limitation(lim)
        if not data.get("supported", True):
            return AgentResult(success=False, blocked=True,
                               error="; ".join(data.get("limitations",
                                   ["Import enumeration not supported for this format."])))
        if data.get("parsed") is False:
            return AgentResult(summary=f"header malformed; imports not enumerated ({data.get('error', '')})")
        needed = data.get("needed", [])
        ctx.profile.attributes["binary_imports"] = needed
        plural = "library" if len(needed) == 1 else "libraries"
        ctx.observe("binary.imports", "Binary analysis", f"{len(needed)} imported {plural}: {needed[:15]}")
        return AgentResult(summary=f"{len(needed)} imported {plural}")

    async def _strings(self, ctx: AgentContext, path: str, data: Dict[str, Any]) -> AgentResult:
        matches = data.get("matches", [])
        n = 0
        for m in matches:
            severity = Severity.HIGH if m["type"] in _STRING_HIGH else Severity.MEDIUM
            f = ctx.candidate(
                title=f"Suspicious embedded string ({m['type']}) in {os.path.basename(path)}",
                category="SuspiciousEmbeddedString", severity=severity, surface="Binary analysis",
                location=f"{path}@offset {m['offset']}",
                description=f"A string matching the '{m['type']}' pattern was found (value masked: "
                            f"{m['value_masked']}).",
                remediation="Remove hardcoded secrets/internal references from the compiled binary; load "
                            "them from a secure secret store at runtime instead.",
                signal={"validator": "binary_suspicious_string", "path": path, "type": m["type"],
                        "offset": m["offset"]})
            n += bool(f)
        if data.get("dangerous_function_references"):
            ctx.observe("binary.strings.dangerous_functions", "Binary analysis",
                        "References to potentially dangerous functions found (informational only, not a "
                        f"finding by itself): {data['dangerous_function_references']}.")
        if data.get("truncated"):
            ctx.state.add_limitation(f"String extraction for {path} was capped at "
                                     f"{data.get('bytes_scanned')} bytes; later file content was not scanned.")
        if data.get("strings_capped"):
            ctx.state.add_limitation(f"String extraction for {path} stopped after the first "
                                     f"{data.get('strings_extracted')} strings; later strings were not scanned.")
        ctx.observe("binary.strings", "Binary analysis",
                    f"{data.get('strings_extracted', 0)} printable string(s) scanned; {n} suspicious match(es).")
        return AgentResult(summary=f"{n} suspicious string match(es)")
