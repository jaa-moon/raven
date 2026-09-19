"""
agents/auth_infra_agent.py
---------------------------
Agent 2: Auth/Infra Attacker.

Attacks authentication mechanisms, session management, hardcoded secrets,
dependency CVEs, and server configuration. Subscribes to FindingsBus for
real-time pivoting when Agent 1 uncovers chain opportunities.
Uses LLM for intelligent analysis of each finding.

When self.use_mcp is True, all tool access routes through the MCP
gateway (self.call_tool). When False, tools are instantiated directly
(legacy path for backward compatibility with `raven scan`).
"""

from __future__ import annotations

import asyncio
from typing import List
from agents.base_agent import BaseAgent
from reports.models import AgentFinding


class AuthInfraAgent(BaseAgent):
    """
    Attacks authentication, configuration, hardcoded secrets, and internal infrastructure.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.pivoted_targets: List[str] = []
        self.bus.subscribe(self._on_finding_discovered)

    def _on_finding_discovered(self, finding: AgentFinding) -> None:
        """Callback triggered when any agent publishes a finding."""
        if finding.agent == "web_api" and finding.chain_opportunity:
            self.pivoted_targets.append(finding.target_url)

    # ── MCP-aware tool helpers ────────────────────────────────────────────────

    def _init_direct_tools(self) -> None:
        """Initialize direct tool instances (legacy path, only when MCP is off)."""
        if not self.use_mcp:
            from tools.auth_tester import AuthTester
            from tools.dep_auditor import DepAuditor
            from tools.port_scanner import PortScanner
            from tools.secret_scanner import SecretScanner
            from tools.http_prober import HttpProber
            self._direct_secret_scanner = SecretScanner(self.profile.path)
            self._direct_auth_tester = AuthTester(self.sandbox.base_url)
            self._direct_dep_auditor = DepAuditor(self.profile.dependencies)
            self._direct_prober = HttpProber(self.sandbox.base_url)

    async def _probe(
        self,
        endpoint: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
        use_form: bool = False,
    ) -> dict:
        """Send HTTP probe — routes through MCP gateway or direct HttpProber."""
        if self.use_mcp:
            result = await self.call_tool(
                "http_probe",
                base_url=self.sandbox.base_url,
                endpoint=endpoint,
                method=method,
                params=params,
                data=data,
                headers=headers,
                use_form=use_form,
            )
            if isinstance(result, dict) and "error" in result and result.get("status_code") is None:
                return {"status_code": 0, "headers": {}, "body": "", "url": "", "elapsed_ms": 0.0, "error": result["error"]}
            return result
        else:
            return await self._direct_prober.probe(endpoint, method, params, data, headers, use_form)

    async def _scan_secrets(self) -> list:
        """Scan for hardcoded secrets — MCP or direct."""
        if self.use_mcp:
            result = await self.call_tool("secret_scan", target_path=str(self.profile.path))
            if isinstance(result, dict) and "items" in result:
                return result["items"]
            elif isinstance(result, dict) and "error" in result:
                return []
            return result if isinstance(result, list) else []
        else:
            return self._direct_secret_scanner.scan()

    async def _audit_deps(self) -> list:
        """Audit dependencies — MCP or direct."""
        if self.use_mcp:
            result = await self.call_tool("dep_audit", dependencies=self.profile.dependencies)
            if isinstance(result, dict) and "items" in result:
                return result["items"]
            elif isinstance(result, dict) and "error" in result:
                return []
            return result if isinstance(result, list) else []
        else:
            return self._direct_dep_auditor.audit()

    async def _test_jwt(self, endpoint: str, sample_jwt: str) -> dict:
        """Test JWT alg:none bypass — MCP or direct."""
        if self.use_mcp:
            result = await self.call_tool(
                "jwt_none_alg",
                base_url=self.sandbox.base_url,
                endpoint=endpoint,
                sample_jwt=sample_jwt,
            )
            if isinstance(result, dict):
                return result
            return {"vulnerable": False, "evidence": str(result)}
        else:
            return await self._direct_auth_tester.test_jwt_none_alg(endpoint, sample_jwt)

    async def _port_scan(self) -> list:
        """Scan ports — MCP or direct."""
        host = self.sandbox.host.replace("http://", "").replace("https://", "")
        if self.use_mcp:
            result = await self.call_tool("port_scan", host=host)
            if isinstance(result, dict) and "items" in result:
                return result["items"]
            elif isinstance(result, dict) and "error" in result:
                return []
            return result if isinstance(result, list) else []
        else:
            from tools.port_scanner import PortScanner
            scanner = PortScanner(host)
            return await scanner.scan()

    # ── Main execution ────────────────────────────────────────────────────────

    async def run(self) -> List[AgentFinding]:
        self.current_action = "Scanning for secrets..."
        self._init_direct_tools()

        # 1. Secret Scanning
        discovered_secrets = await self._scan_secrets()
        for sec in discovered_secrets:
            analysis = await self.ask_llm(
                "You are a security engineer. Analyze this hardcoded secret finding. Explain the risk, attack scenarios, and remediation.",
                f"File: {sec['file']}, Line: {sec.get('line', '?')}\n"
                f"Type: {sec['type']}\n"
                f"Match: {sec['match']}"
            )
            finding = AgentFinding(
                agent="auth_infra",
                vulnerability_type="HardcodedSecret",
                severity="High",
                target_url=sec["file"],
                method="STATIC",
                parameter=sec["type"],
                payload_sent="",
                evidence=f"Line {sec.get('line', '?')}: {sec['match']}",
                confirmed=True,
                ai_analysis=analysis or f"Hardcoded {sec['type']} found in {sec['file']}. Leaked credentials enable unauthorized access.",
                curl_poc="",
                remediation="Remove secrets from source code. Use environment variables, a .env file (git-ignored), or a secrets manager.",
                chain_opportunity=f"Use leaked {sec['type']} from {sec['file']} for privilege escalation"
            )
            self.publish_finding(finding)

        # 2. Dependency Vulnerability Audit
        self.current_action = "Auditing dependencies..."
        dep_issues = await self._audit_deps()
        for issue in dep_issues:
            analysis = await self.ask_llm(
                "You are a security engineer. Analyze this vulnerable dependency. Explain the known CVEs, attack vectors, and upgrade path.",
                f"Package: {issue['package']}\nVulnerability hint: {issue['cve_hint']}"
            )
            finding = AgentFinding(
                agent="auth_infra",
                vulnerability_type="VulnerableDependency",
                severity="Medium",
                target_url="requirements.txt / package.json",
                method="AUDIT",
                parameter=issue["package"],
                payload_sent="",
                evidence=issue["cve_hint"],
                confirmed=True,
                ai_analysis=analysis or f"Known vulnerabilities in {issue['package']}.",
                curl_poc="",
                remediation=f"Upgrade {issue['package']} to the latest stable version.",
                chain_opportunity=None
            )
            self.publish_finding(finding)

        # 3. Server Configuration & Security Headers
        self.current_action = "Checking server configuration..."
        await self._check_security_headers()
        await self._check_debug_mode()
        await self._check_cors_misconfiguration()

        # 4. Session Cookie Security
        self.current_action = "Checking session cookie security..."
        await self._check_session_cookies()

        # 5. Port Scanning
        self.current_action = "Scanning for open ports..."
        await self._run_port_scan()

        # 6. JWT and Auth Bypass Probing
        self.current_action = "Testing authentication routes..."
        sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        auth_paths = [p for p in (self.profile.detected_routes or []) if any(k in p for k in ["admin", "api", "auth", "login", "user"])]
        for path in auth_paths[:5]:
            jwt_res = await self._test_jwt(path, sample_jwt)
            if jwt_res.get("vulnerable"):
                finding = AgentFinding(
                    agent="auth_infra",
                    vulnerability_type="JWT_Alg_None_Bypass",
                    severity="Critical",
                    target_url=f"{self.sandbox.base_url}{path}",
                    method="GET",
                    parameter="Authorization",
                    payload_sent=jwt_res["payload"],
                    evidence=jwt_res["evidence"],
                    confirmed=True,
                    ai_analysis="Server accepted JWT with 'alg: none', bypassing signature verification.",
                    curl_poc=f"curl -H 'Authorization: Bearer {jwt_res['payload']}' '{self.sandbox.base_url}{path}'",
                    remediation="Enforce signature algorithm in JWT parser. Reject 'none' algorithm.",
                    chain_opportunity="Forge arbitrary admin tokens for full administrative access."
                )
                self.publish_finding(finding)

        # 7. Default Credentials Testing
        self.current_action = "Testing default credentials..."
        await self._test_default_credentials(auth_paths)

        # 8. Real-time Pivoting on Agent 1 Discoveries
        if self.pivoted_targets:
            self.current_action = f"Pivoting on {len(self.pivoted_targets)} Agent 1 discoveries..."
            for target_url in self.pivoted_targets:
                jwt_pivot = await self._test_jwt(target_url, sample_jwt)
                if jwt_pivot.get("vulnerable"):
                    finding = AgentFinding(
                        agent="auth_infra",
                        vulnerability_type="ChainedAuthBypass",
                        severity="Critical",
                        target_url=target_url,
                        method="GET",
                        parameter="Authorization",
                        payload_sent=jwt_pivot["payload"],
                        evidence=jwt_pivot["evidence"],
                        confirmed=True,
                        ai_analysis=f"Pivoted from Agent 1 finding at {target_url} — confirmed JWT bypass.",
                        curl_poc=f"curl -H 'Authorization: Bearer {jwt_pivot['payload']}' '{target_url}'",
                        remediation="Enforce strict auth middleware on all routes.",
                        chain_opportunity="Chained injection + auth bypass = full compromise"
                    )
                    self.publish_finding(finding)

        self.current_action = "Auth & Infra attack phase complete."
        return self.findings

    async def _check_security_headers(self) -> None:
        """Check for missing security headers."""
        res = await self._probe("/")
        if res["error"] or res["status_code"] == 0:
            return

        headers = {k.lower(): v for k, v in res["headers"].items()}
        missing = []

        security_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY or SAMEORIGIN",
            "x-xss-protection": "1; mode=block",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
        }

        for header, recommended in security_headers.items():
            if header not in headers:
                missing.append(f"Missing {header} (recommended: {recommended})")

        if missing:
            finding = AgentFinding(
                agent="auth_infra",
                vulnerability_type="MissingSecurityHeaders",
                severity="Low",
                target_url=f"{self.sandbox.base_url}/",
                method="GET",
                parameter="HTTP Headers",
                payload_sent="",
                evidence="\n".join(missing),
                confirmed=True,
                ai_analysis=f"The server is missing {len(missing)} security headers, leaving the application vulnerable to clickjacking, MIME sniffing, and XSS attacks.",
                curl_poc=f"curl -I '{self.sandbox.base_url}/'",
                remediation="Add security headers via middleware or web server configuration.",
                chain_opportunity=None
            )
            self.publish_finding(finding)

    async def _check_debug_mode(self) -> None:
        """Check if the application is running in debug mode."""
        # Try to trigger a 404 and check for debug info
        res = await self._probe("/raven_test_nonexistent_route_debug_check")
        if res["error"] or res["status_code"] == 0:
            return

        body_lower = res["body"].lower()
        debug_signatures = ["werkzeug debugger", "traceback", "debug = true",
                           "django debug", "stack trace", "debugger"]

        for sig in debug_signatures:
            if sig in body_lower:
                finding = AgentFinding(
                    agent="auth_infra",
                    vulnerability_type="DebugModeEnabled",
                    severity="High",
                    target_url=f"{self.sandbox.base_url}/",
                    method="GET",
                    parameter="Application Config",
                    payload_sent="",
                    evidence=f"Debug mode signature '{sig}' detected in error response.",
                    confirmed=True,
                    ai_analysis="Debug mode is enabled in production, exposing stack traces, source code, and potentially allowing arbitrary code execution via the Werkzeug debugger console.",
                    curl_poc=f"curl '{self.sandbox.base_url}/raven_test_nonexistent_route_debug_check'",
                    remediation="Disable debug mode in production. Set DEBUG=False or debug=False.",
                    chain_opportunity="Debug mode exposes source code and enables interactive code execution"
                )
                self.publish_finding(finding)
                return

    async def _check_cors_misconfiguration(self) -> None:
        """Check for CORS misconfiguration allowing arbitrary origins."""
        evil_origin = "https://evil-attacker.com"
        res = await self._probe("/", method="GET", headers={"Origin": evil_origin})
        if res["error"] or res["status_code"] == 0:
            return

        acao = res["headers"].get("access-control-allow-origin", "")
        acac = res["headers"].get("access-control-allow-credentials", "")

        if acao == "*" or acao == evil_origin:
            severity = "High" if acac.lower() == "true" else "Medium"
            finding = AgentFinding(
                agent="auth_infra",
                vulnerability_type="CORS_Misconfiguration",
                severity=severity,
                target_url=f"{self.sandbox.base_url}/",
                method="GET",
                parameter="Origin",
                payload_sent=evil_origin,
                evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                confirmed=True,
                ai_analysis=f"The server reflects arbitrary origins in CORS headers{' with credentials allowed' if acac.lower() == 'true' else ''}. This allows cross-origin requests from any domain, potentially leaking sensitive data.",
                curl_poc=f"curl -H 'Origin: {evil_origin}' -I '{self.sandbox.base_url}/'",
                remediation="Configure CORS to only allow trusted origins. Never reflect arbitrary Origin headers. Avoid Access-Control-Allow-Credentials: true with wildcard origins.",
                chain_opportunity="CORS misconfiguration enables cross-site data theft via malicious JavaScript"
            )
            self.publish_finding(finding)

    async def _check_session_cookies(self) -> None:
        """Check session cookie security attributes (HttpOnly, Secure, SameSite)."""
        res = await self._probe("/")
        if res["error"] or res["status_code"] == 0:
            return

        set_cookie_headers = []
        for k, v in res["headers"].items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

        for cookie_str in set_cookie_headers:
            cookie_lower = cookie_str.lower()
            issues = []

            # Only check session-like cookies
            is_session = any(name in cookie_lower for name in ["session", "sid", "token", "auth", "jwt"])
            if not is_session:
                continue

            if "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag (cookie accessible via JavaScript)")
            if "secure" not in cookie_lower:
                issues.append("Missing Secure flag (cookie sent over HTTP)")
            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite attribute (vulnerable to CSRF)")

            if issues:
                finding = AgentFinding(
                    agent="auth_infra",
                    vulnerability_type="InsecureSessionCookie",
                    severity="Medium",
                    target_url=f"{self.sandbox.base_url}/",
                    method="GET",
                    parameter="Set-Cookie",
                    payload_sent="",
                    evidence=f"Cookie: {cookie_str[:100]}...\nIssues:\n" + "\n".join(f"- {i}" for i in issues),
                    confirmed=True,
                    ai_analysis=f"Session cookie has {len(issues)} security issue(s): {'; '.join(issues)}",
                    curl_poc=f"curl -I '{self.sandbox.base_url}/'",
                    remediation="Set HttpOnly, Secure, and SameSite=Lax (or Strict) on all session cookies.",
                    chain_opportunity="Insecure cookies can be stolen via XSS or intercepted over HTTP"
                )
                self.publish_finding(finding)

    async def _run_port_scan(self) -> None:
        """Scan for unexpected open ports on the sandbox host."""
        try:
            open_ports = await self._port_scan()

            # Filter out the expected application port
            unexpected = [p for p in open_ports if p != self.sandbox.port]

            if unexpected:
                port_services = {
                    21: "FTP", 22: "SSH", 3306: "MySQL", 5432: "PostgreSQL",
                    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
                    8080: "HTTP-Alt", 443: "HTTPS", 80: "HTTP"
                }
                port_details = [f"{p} ({port_services.get(p, 'Unknown')})" for p in unexpected]
                finding = AgentFinding(
                    agent="auth_infra",
                    vulnerability_type="UnexpectedOpenPorts",
                    severity="Medium",
                    target_url=self.sandbox.host,
                    method="TCP",
                    parameter="Port Scan",
                    payload_sent=f"Scanned ports: {', '.join(str(p) for p in open_ports)}",
                    evidence=f"Unexpected open ports: {', '.join(port_details)}",
                    confirmed=True,
                    ai_analysis=f"Found {len(unexpected)} unexpected open port(s) beyond the application port ({self.sandbox.port}). Exposed services like databases or admin interfaces can be directly attacked.",
                    curl_poc="",
                    remediation="Close unnecessary ports. Bind internal services to 127.0.0.1 only. Use firewall rules to restrict access.",
                    chain_opportunity=f"Open ports {', '.join(str(p) for p in unexpected)} may expose databases or admin panels"
                )
                self.publish_finding(finding)
        except Exception:
            pass

    async def _test_default_credentials(self, auth_paths: list) -> None:
        """Test common default credentials on login endpoints."""
        login_paths = [p for p in auth_paths if any(k in p.lower() for k in ["login", "auth", "signin"])]
        if not login_paths:
            login_paths = ["/login", "/admin/login", "/api/auth/login"]

        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
            ("user", "password"),
        ]

        for path in login_paths[:3]:
            for username, password in default_creds:
                res = await self._probe(
                    path,
                    method="POST",
                    data={"username": username, "password": password},
                    use_form=True
                )

                # Check for signs of successful login
                if res["status_code"] == 0 or res["error"]:
                    continue

                body_lower = res["body"].lower()
                headers = res["headers"]

                login_success = (
                    (res["status_code"] in (200, 302) and any(k in body_lower for k in ["welcome", "dashboard", "logout", "token", "session"]))
                    or (res["status_code"] == 302 and any(k in headers.get("location", "").lower() for k in ["dashboard", "home", "admin"]))
                    or ("set-cookie" in {k.lower() for k in headers} and res["status_code"] in (200, 302))
                )

                if login_success:
                    finding = AgentFinding(
                        agent="auth_infra",
                        vulnerability_type="DefaultCredentials",
                        severity="Critical",
                        target_url=f"{self.sandbox.base_url}{path}",
                        method="POST",
                        parameter="username/password",
                        payload_sent=f"username={username}&password={password}",
                        evidence=f"Login appeared successful with {username}:{password} (HTTP {res['status_code']})\n{res['body'][:300]}",
                        confirmed=True,
                        ai_analysis=f"Default credentials {username}:{password} accepted at {path}. Attackers can gain immediate access without any exploit.",
                        curl_poc=f"curl -X POST -d 'username={username}&password={password}' '{self.sandbox.base_url}{path}'",
                        remediation="Change all default credentials. Enforce strong password policies. Implement account lockout after failed attempts.",
                        chain_opportunity=f"Default creds on {path} provide direct admin access"
                    )
                    self.publish_finding(finding)
                    return  # Stop after first confirmed default cred
