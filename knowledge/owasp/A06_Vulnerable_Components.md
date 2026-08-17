# OWASP A06:2021 — Vulnerable and Outdated Components

## Description

A06 covers the use of software components (libraries, frameworks, other modules) with
known vulnerabilities. Components run with the same privileges as the application, so
a vulnerability in a component can lead to data loss, takeover, or server compromise.

## Risk

- **CVSS Range**: Varies (can be Critical)
- **Impact**: Varies by CVE — from information disclosure to full RCE
- **CWE Coverage**: CWE-1035, CWE-1104, CWE-1395

## Common Examples

### Outdated Python Package
```
# requirements.txt
Flask==2.0.2   # CVE-2023-30861 — Vary header not set correctly (session leakage)
requests==2.18.0  # Multiple historical CVEs
```

### Outdated npm Package
```json
{
  "dependencies": {
    "axios": "0.18.0",   // CVE-2019-10742 — ReDoS
    "lodash": "4.0.0"    // CVE-2019-10744 — Prototype Pollution
  }
}
```

## Detection Tools

- **Python**: `pip-audit -r requirements.txt`
- **JavaScript**: `npm audit` or `yarn audit`
- **Go**: `govulncheck ./...`
- **All**: GitHub Dependabot, Snyk, OWASP Dependency-Check

## Remediation Checklist

- [ ] Maintain an inventory of all components and their versions
- [ ] Subscribe to security advisories for your core dependencies
- [ ] Use `pip-audit`, `npm audit`, or `govulncheck` in your CI/CD pipeline
- [ ] Pin dependency versions in `requirements.txt` / `package-lock.json`
- [ ] Upgrade vulnerable packages to their patched versions promptly
- [ ] Remove unused dependencies to reduce attack surface
- [ ] Consider automated dependency updates (Dependabot, Renovate)
