"""
agents/source.py
----------------
Source-tree assessment: secrets, dependencies, static patterns, configuration.
Tasks are proposed from what the target analysis found (e.g. dependencies are
only audited when manifests exist).
"""

from __future__ import annotations

import os
from typing import List

from agents.base import Agent, AgentContext, AgentResult
from core.models import Severity, TestTask
from core.profile import TargetProfile
from core.state import AssessmentState

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


def _rel(root: str, file: str) -> str:
    return os.path.relpath(file, root) if os.path.isabs(file) else file


class SourceAssessmentAgent(Agent):
    name = "source_assessment"
    description = "Assesses a source tree for secrets, vulnerable dependencies, unsafe code and misconfiguration."
    capabilities = ["secret_detection", "dependency_audit", "static_code_analysis", "config_audit",
                    "permission_audit"]

    def applies(self, profile: TargetProfile) -> bool:
        return profile.target_type == "source_repository" and profile.source_available

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        p = state.profile
        tasks = [
            self.task("secrets", "secret_detection", "Secrets", "Scan for hardcoded credentials", priority=90),
            self.task("code", "static_code_analysis", "Source code", "Static analysis for unsafe constructs",
                      priority=70),
            self.task("config", "config_audit", "Configuration", "Audit configuration files", priority=60),
        ]
        if p.attributes.get("manifests"):
            tasks.append(self.task("deps", "dependency_audit", "Dependencies", "Audit declared dependencies",
                                   priority=80, rationale=f"Manifests found: {p.attributes['manifests']}"))
        tasks.append(self.task("perms", "permission_audit", "File permissions", "Audit file permissions",
                               priority=40))
        return tasks

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        root = ctx.profile.attributes["root"]
        res = await ctx.call(task.capability, {"path": root}, task.title)
        if not res.ok:
            return AgentResult(success=False, blocked=res.status in ("out_of_scope", "tool_unavailable"),
                               error=res.error)
        step = task.key.split(".", 1)[1]
        n = await getattr(self, f"_{step}")(ctx, root, res.data)
        return AgentResult(summary=f"{n} candidate(s)")

    async def _secrets(self, ctx: AgentContext, root: str, data: dict) -> int:
        n = 0
        for m in data.get("matches", []):
            f = ctx.candidate(
                title=f"Possible {m['type'] if m['type'].lower().startswith('hardcoded') else 'hardcoded ' + m['type']} in {m['file']}", category="HardcodedSecret",
                severity=Severity.HIGH, surface="Secrets", location=f"{m['file']}:{m['line']}",
                description=f"A {m['type']} pattern matched (value masked: {m['masked']}).",
                impact="Credential exposure to anyone with repository access.",
                remediation="Revoke the credential, move it to a secret store or environment variable.",
                reproduction=[f"Open {m['file']} at line {m['line']}"],
                signal={"validator": "secret_in_file", "root": root, "file": m["file"], "line": m["line"]})
            n += bool(f)
        ctx.observe("secrets.scan", "Secrets", f"{len(data.get('matches', []))} pattern match(es).")
        return n

    async def _code(self, ctx: AgentContext, root: str, data: dict) -> int:
        n = 0
        for i in data.get("issues", []):
            f = ctx.candidate(
                title=f"{i['description']} ({i['file']}:{i['line']})", category="CodePattern",
                severity=_SEV.get(i["severity"], Severity.LOW), surface="Source code",
                location=f"{i['file']}:{i['line']}", description=f"{i['description']} [{i['cwe']}]: {i['snippet']}",
                remediation="Replace with a safe API or validate/escape all untrusted input.",
                reproduction=[f"Open {i['file']} at line {i['line']}"],
                signal={"validator": "code_pattern", "root": root, "rule": i["rule"],
                        "file": i["file"], "line": i["line"]})
            n += bool(f)
        ctx.observe("code.scan", "Source code", f"{len(data.get('issues', []))} pattern hit(s) in "
                    f"{data.get('files_scanned', 0)} file(s).")
        return n

    async def _config(self, ctx: AgentContext, root: str, data: dict) -> int:
        n = 0
        for i in data.get("issues", []):
            rel = _rel(root, i.get("file", ""))
            f = ctx.candidate(
                title=f"{i.get('name', 'Insecure configuration')} in {rel}", category="SecurityMisconfiguration",
                severity=_SEV.get(str(i.get("severity", "medium")).lower(), Severity.MEDIUM), surface="Configuration",
                location=f"{rel}:{i.get('line')}", description=i.get("description", ""),
                remediation="Use secure production defaults.",
                signal={"validator": "config_setting", "root": root, "file": rel, "line": i.get("line", 1),
                        "line_content": str(i.get("line_content", ""))[:120]})
            n += bool(f)
        ctx.observe("config.scan", "Configuration", f"{data.get('files_scanned', 0)} config file(s) scanned.")
        return n

    async def _deps(self, ctx: AgentContext, root: str, data: dict) -> int:
        n = 0
        for v in data.get("vulnerabilities", []):
            f = ctx.candidate(
                title=f"Vulnerable dependency {v['package']}=={v['version']}", category="VulnerableDependency",
                severity=Severity.MEDIUM, surface="Dependencies", location=v["manifest"],
                description=v.get("advisory", ""), remediation=f"Upgrade {v['package']} to >= {v['fixed_in']}.",
                reproduction=[f"grep -i {v['package']} {v['manifest']}"],
                signal={"validator": "vulnerable_dependency", "root": root, "manifest": v["manifest"],
                        "package": v["package"], "version": v["version"], "fixed_in": v["fixed_in"]})
            n += bool(f)
        ctx.observe("deps.audit", "Dependencies", f"{data.get('dependencies', 0)} dependencies checked.")
        return n

    async def _perms(self, ctx: AgentContext, root: str, data: dict) -> int:
        n = 0
        for i in data.get("issues", []):
            f = ctx.candidate(
                title=f"{i.get('issue', 'Insecure permission')}: {_rel(root, i.get('file', ''))}",
                category="InsecurePermissions", severity=_SEV.get(str(i.get("severity", "medium")).lower(), Severity.MEDIUM),
                surface="File permissions", location=i.get("file", ""), description=i.get("details", ""),
                remediation="Restrict permissions (e.g. chmod 600/750).",
                signal={"validator": "file_permission", "path": i.get("file", ""), "issue": i.get("issue", "")})
            n += bool(f)
        ctx.observe("perms.scan", "File permissions", f"{len(data.get('issues', []))} permission issue(s) found.")
        return n
