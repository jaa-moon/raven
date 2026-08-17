# CWE-78: OS Command Injection

## Description

OS Command Injection (CWE-78) occurs when an application constructs an operating system
command using externally-influenced input. If the input is not properly validated or
sanitized, an attacker can modify the intended command or inject additional commands.

## Risk

- **CVSS Score**: Up to 9.8 (Critical)
- **Impact**: Full system compromise, arbitrary command execution as the application user
- **OWASP**: A03:2021 — Injection
- **Affected Languages**: Python, JavaScript, Go, PHP, Java, Ruby

## Vulnerable Example (Python)

```python
# VULNERABLE: user input injected directly into shell command
import subprocess
hostname = request.args.get("host")
output = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)

# Attacker sends: host=localhost; rm -rf /
# Result: ping runs AND rm -rf / executes
```

## Safe Example (Python)

```python
# SAFE: use list of args with shell=False (default)
import subprocess
import shlex
hostname = request.args.get("host", "")
# Validate input strictly
if not hostname.replace(".", "").isalnum():
    raise ValueError("Invalid hostname")
output = subprocess.run(["ping", "-c", "1", hostname], capture_output=True, shell=False)
```

## Remediation

1. **Never pass user input directly to shell commands.**
2. Use `subprocess` with `shell=False` and pass arguments as a list.
3. Whitelist allowed characters in user-supplied parameters.
4. Apply the principle of least privilege — run the application with minimal OS permissions.
5. Use dedicated libraries for tasks like DNS lookups instead of shelling out.
