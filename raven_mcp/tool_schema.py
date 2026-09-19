"""
mcp/tool_schema.py
------------------
Defines the MCP tool schemas for Raven's autonomous agent mode.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class ToolParam(BaseModel):
    name: str
    type: str
    description: str
    required: bool = True
    default: Any = None


class ToolSchema(BaseModel):
    name: str
    server: str = ""                        # External MCP server name (legacy)
    server_group: str = ""                  # Logical group: network, recon, exploit, auth, secrets
    module: str = ""                        # Python module path for in-process resolution
    function: str = ""                      # Function name within the module
    description: str
    params: List[ToolParam]
    timeout_seconds: int = 10
    requires_sandbox: bool = True


ALL_TOOLS: List[ToolSchema] = [
    # ── NETWORK ──────────────────────────────────────────────────────────────
    ToolSchema(
        name="http_probe",
        server="network_server",
        server_group="network",
        module="tools.http_prober",
        function="probe",
        description=(
            "Sends an HTTP request to a target endpoint and returns status code, "
            "headers, response time, and body snippet. Use to baseline an endpoint "
            "before probing with payloads. Best first call on any discovered URL."
        ),
        params=[
            ToolParam(name="base_url", type="string", description="Base URL of the target application", required=True),
            ToolParam(name="endpoint", type="string", description="Endpoint path to probe", required=True),
            ToolParam(name="method", type="string", description="HTTP method", required=False, default="GET"),
            ToolParam(name="params", type="dict", description="Query parameters", required=False, default=None),
            ToolParam(name="data", type="dict", description="Body data for POST/PUT", required=False, default=None),
            ToolParam(name="headers", type="dict", description="Custom headers", required=False, default=None),
            ToolParam(name="use_form", type="bool", description="Send as form-encoded instead of JSON", required=False, default=False),
        ],
        timeout_seconds=10,
    ),
    ToolSchema(
        name="http_probe_batch",
        server="network_server",
        server_group="network",
        module="tools.http_prober",
        function="probe_batch",
        description=(
            "Probes an endpoint with multiple payloads on a single parameter. "
            "Returns all response results for comparative analysis."
        ),
        params=[
            ToolParam(name="base_url", type="string", description="Base URL of the target application", required=True),
            ToolParam(name="endpoint", type="string", description="Endpoint path to probe", required=True),
            ToolParam(name="payloads", type="list", description="List of payload strings to test", required=True),
            ToolParam(name="param_name", type="string", description="Parameter name to inject into", required=False, default="q"),
            ToolParam(name="method", type="string", description="HTTP method", required=False, default="GET"),
        ],
        timeout_seconds=30,
    ),
    ToolSchema(
        name="port_scan",
        server="network_server",
        server_group="network",
        module="tools.port_scanner",
        function="scan",
        description=(
            "Scans common TCP ports on the sandbox host to discover exposed "
            "internal services. Use when looking for databases, caches, or admin "
            "interfaces not linked from the web UI."
        ),
        params=[
            ToolParam(name="host", type="string", description="Target hostname or IP", required=True),
            ToolParam(name="ports", type="list", description="List of port numbers to scan", required=False, default=None),
        ],
        timeout_seconds=15,
    ),

    # ── RECON ────────────────────────────────────────────────────────────────
    ToolSchema(
        name="dir_fuzz",
        server="recon_server",
        server_group="recon",
        module="tools.dir_fuzzer",
        function="fuzz",
        description=(
            "Fuzzes the target web server to discover hidden routes and endpoints "
            "using a built-in wordlist. Returns list of (path, status_code) tuples."
        ),
        params=[
            ToolParam(name="base_url", type="string", description="Base URL to fuzz", required=True),
            ToolParam(name="wordlist", type="list", description="Custom wordlist of paths to test", required=False, default=None),
        ],
        timeout_seconds=15,
    ),

    # ── AUTH ──────────────────────────────────────────────────────────────────
    ToolSchema(
        name="jwt_none_alg",
        server="auth_server",
        server_group="auth",
        module="tools.auth_tester",
        function="test_jwt_none_alg",
        description=(
            "Attempts JWT algorithm 'none' signature bypass on a target endpoint. "
            "Use when a JWT token is present in Authorization header or cookies."
        ),
        params=[
            ToolParam(name="base_url", type="string", description="Base URL of the target application", required=True),
            ToolParam(name="endpoint", type="string", description="Endpoint path to test", required=True),
            ToolParam(name="sample_jwt", type="string", description="A valid sample JWT token", required=True),
        ],
        timeout_seconds=10,
    ),
    ToolSchema(
        name="jwt_empty_sig",
        server="auth_server",
        server_group="auth",
        module="tools.auth_tester",
        function="test_jwt_empty_sig",
        description=(
            "Tests if the server accepts a JWT with an empty signature "
            "(signature stripping attack)."
        ),
        params=[
            ToolParam(name="base_url", type="string", description="Base URL of the target application", required=True),
            ToolParam(name="endpoint", type="string", description="Endpoint path to test", required=True),
            ToolParam(name="sample_jwt", type="string", description="A valid sample JWT token", required=True),
        ],
        timeout_seconds=10,
    ),
    ToolSchema(
        name="jwt_role_escalation",
        server="auth_server",
        server_group="auth",
        module="tools.auth_tester",
        function="test_jwt_role_escalation",
        description=(
            "Attempts to modify JWT payload to escalate role to admin "
            "using alg:none header."
        ),
        params=[
            ToolParam(name="base_url", type="string", description="Base URL of the target application", required=True),
            ToolParam(name="endpoint", type="string", description="Endpoint path to test", required=True),
            ToolParam(name="sample_jwt", type="string", description="A valid sample JWT token", required=True),
        ],
        timeout_seconds=10,
    ),
    ToolSchema(
        name="cookie_audit",
        server="auth_server",
        server_group="auth",
        module="tools.auth_tester",
        function="check_cookie_security",
        description=(
            "Audits cookie security flags: HttpOnly, Secure, SameSite. "
            "Checks for session cookies missing security attributes."
        ),
        params=[
            ToolParam(name="base_url", type="string", description="Base URL of the target application", required=True),
            ToolParam(name="endpoint", type="string", description="Endpoint path to analyze cookies", required=False, default="/"),
        ],
        timeout_seconds=10,
    ),

    # ── SECRETS ──────────────────────────────────────────────────────────────
    ToolSchema(
        name="secret_scan",
        server="secrets_server",
        server_group="secrets",
        module="tools.secret_scanner",
        function="scan_secrets",
        description=(
            "Scans project source files for hardcoded secrets, API keys, "
            "passwords, and sensitive configuration using regex patterns "
            "and entropy analysis."
        ),
        params=[
            ToolParam(name="target_path", type="string", description="Path to the project directory to scan", required=True),
        ],
        timeout_seconds=30,
        requires_sandbox=False,
    ),
    ToolSchema(
        name="dep_audit",
        server="secrets_server",
        server_group="secrets",
        module="tools.dep_auditor",
        function="audit_deps",
        description=(
            "Checks project dependencies for known CVEs using pip-audit (Python), "
            "npm audit (Node), or a built-in vulnerability database."
        ),
        params=[
            ToolParam(name="dependencies", type="list", description="List of dependency strings (e.g. ['flask==2.2.0', 'requests'])", required=True),
        ],
        timeout_seconds=60,
        requires_sandbox=False,
    ),

    # ── ADVANCED NETWORK & SERVICE PROBES ─────────────────────────────────────
    ToolSchema(
        name="banner_grab",
        server="network_server",
        server_group="network",
        module="tools.banner_grabber",
        function="grab",
        description=(
            "Connects to a TCP port, retrieves the initial service greeting/banner, "
            "and determines if TLS is required or active."
        ),
        params=[
            ToolParam(name="host", type="string", description="Target host or IP address", required=True),
            ToolParam(name="port", type="int", description="Target TCP port", required=True),
            ToolParam(name="timeout", type="float", description="Connection timeout in seconds", required=False, default=3.0),
        ],
        timeout_seconds=10,
    ),
    ToolSchema(
        name="protocol_probe",
        server="network_server",
        server_group="network",
        module="tools.protocol_prober",
        function="probe",
        description=(
            "Probes network services with application-specific protocol handshakes "
            "(Redis, MySQL, FTP, SMTP, Memcached, HTTP, SSH) to determine version and auth state."
        ),
        params=[
            ToolParam(name="host", type="string", description="Target host or IP address", required=True),
            ToolParam(name="port", type="int", description="Target TCP port", required=True),
            ToolParam(name="protocol", type="string", description="Specific protocol or auto", required=False, default="auto"),
            ToolParam(name="timeout", type="float", description="Probe timeout in seconds", required=False, default=3.0),
        ],
        timeout_seconds=10,
    ),
    ToolSchema(
        name="default_creds_test",
        server="auth_server",
        server_group="auth",
        module="tools.default_creds_tester",
        function="test_creds",
        description=(
            "Audits exposed network services for unauthenticated access or known "
            "default developer/factory credentials (Redis, FTP, HTTP Basic Auth, PostgreSQL)."
        ),
        params=[
            ToolParam(name="host", type="string", description="Target host or IP address", required=True),
            ToolParam(name="port", type="int", description="Target TCP port", required=True),
            ToolParam(name="service", type="string", description="Service type (http, ftp, redis, postgres)", required=False, default="http"),
            ToolParam(name="custom_creds", type="list", description="Optional list of custom credential dicts", required=False, default=None),
            ToolParam(name="timeout", type="float", description="Timeout in seconds", required=False, default=3.0),
        ],
        timeout_seconds=15,
    ),

    # ── BINARY & PROCESS ─────────────────────────────────────────────────────
    ToolSchema(
        name="process_probe",
        server="binary_server",
        server_group="binary",
        module="tools.process_prober",
        function="probe",
        description=(
            "Inspects local running processes, open ports/sockets, command-line arguments, "
            "and sanitized environment variables."
        ),
        params=[
            ToolParam(name="pid", type="int", description="Target process ID", required=False, default=None),
            ToolParam(name="name", type="string", description="Process name filter", required=False, default=None),
            ToolParam(name="port", type="int", description="Listening port filter", required=False, default=None),
        ],
        timeout_seconds=10,
        requires_sandbox=False,
    ),
    ToolSchema(
        name="cli_fuzz",
        server="binary_server",
        server_group="binary",
        module="tools.cli_fuzzer",
        function="fuzz",
        description=(
            "Executes a CLI binary with boundary inputs, format strings, and special characters "
            "to check for crashes, unhandled exceptions, and memory faults."
        ),
        params=[
            ToolParam(name="binary_path", type="string", description="Path to binary executable", required=True),
            ToolParam(name="base_args", type="list", description="Base argument list", required=False, default=None),
            ToolParam(name="custom_payloads", type="list", description="Custom boundary payloads", required=False, default=None),
            ToolParam(name="timeout", type="float", description="Per-execution timeout in seconds", required=False, default=5.0),
        ],
        timeout_seconds=30,
        requires_sandbox=True,
    ),

    # ── INFRASTRUCTURE & CONFIGURATION ───────────────────────────────────────
    ToolSchema(
        name="config_scan",
        server="infra_server",
        server_group="infra",
        module="tools.config_scanner",
        function="scan",
        description=(
            "Scans project configuration files (.env, yaml, json, docker-compose) "
            "for debug mode, weak keys, disabled TLS verification, and insecure defaults."
        ),
        params=[
            ToolParam(name="path", type="string", description="Directory or config file path to scan", required=False, default="."),
        ],
        timeout_seconds=20,
        requires_sandbox=False,
    ),
    ToolSchema(
        name="permission_scan",
        server="infra_server",
        server_group="infra",
        module="tools.permission_scanner",
        function="scan",
        description=(
            "Audits local filesystem and file permissions for world-writable sensitive files, "
            "overly permissive keys, and SUID binaries."
        ),
        params=[
            ToolParam(name="path", type="string", description="Directory or file path to audit", required=False, default="."),
        ],
        timeout_seconds=20,
        requires_sandbox=False,
    ),
]
