# Secrets Server Tools
Provides tools for static analysis of hardcoded secrets and dependency vulnerabilities. These tools do not require a running sandbox.

## env_scan
Scans environment files (.env) and configuration files for exposed secrets.

## key_detect
Scans source code statically for hardcoded API keys, passwords, tokens, and credentials.

## dep_audit
Audits third-party dependencies defined in package files (e.g., requirements.txt, package.json) for known CVEs.
