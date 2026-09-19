# Methodology: Infrastructure & Configuration Security Assessment

## 1. When to Use
Activate this methodology when assessing source repositories, container configurations (`Dockerfile`, `docker-compose.yml`), Kubernetes manifests, environment configuration files (`.env`), or server settings.

## 2. Key Hypotheses
- **H-INF-01**: Sensitive environment files (`.env`, `.env.production`) or private keys committed to source control.
- **H-INF-02**: Debug mode or verbose trace output enabled in configuration files (`DEBUG=True`).
- **H-INF-03**: Container execution defaults to root user without an explicit `USER` directive.
- **H-INF-04**: Containers running in privileged mode (`privileged: true`) or mounting host root volumes (`/:/host`).
- **H-INF-05**: TLS certificate validation explicitly disabled in code or configuration (`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).

## 3. Recommended Tools
- `config_scan`: Static configuration scanner checking patterns in `.env`, YAML, JSON, Dockerfiles.
- `secret_scan`: Pattern and entropy scanner for credentials, tokens, and private keys.
- `permission_scan`: Local filesystem permission checks on configuration directories.
- `dep_audit`: Scanning third-party dependencies for known CVEs.

## 4. Evidence Criteria
- **Committed Secret / Key**: Raw file path and line number with high-entropy token or private key header.
- **Misconfiguration**: Raw configuration file snippet with line number showing insecure directive.
- **Privileged Container**: Docker compose or Kubernetes manifest showing `privileged: true` or `hostNetwork: true`.
- **PoC Format**: Exact file path and line reference with reproduction instructions.

## 5. Common False Positives
- Sample or template environment files (`.env.example`) containing mock placeholder tokens.
- Test suite configuration files with mock credentials for unit tests.
- Internal test certificates intentionally marked with self-signed authority.
