# OWASP A03:2021 — Injection

## Description

Injection vulnerabilities occur when hostile data is sent to an interpreter as part
of a command or query. The attacker's data can trick the interpreter into executing
unintended commands or accessing unauthorized data.

Injection covers: SQL Injection, Command Injection, LDAP Injection, XPath Injection,
NoSQL Injection, Template Injection (SSTI), and Code Injection.

## Risk

- **CVSS Range**: 5.0 – 9.8
- **Impact**: Data theft, authentication bypass, Remote Code Execution, full system compromise
- **CWE Coverage**: CWE-77, CWE-78, CWE-79, CWE-89, CWE-90, CWE-94

## Common Vulnerable Patterns

### SQL Injection
```python
# VULNERABLE
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)

# SAFE
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
```

### Command Injection
```python
# VULNERABLE
output = subprocess.check_output(f"ping {host}", shell=True)

# SAFE
output = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
```

### Server-Side Template Injection (SSTI)
```python
# VULNERABLE — Flask/Jinja2
from flask import render_template_string
template = f"Hello {request.args.get('name')}"
return render_template_string(template)  # {{7*7}} returns 49

# SAFE
return render_template("hello.html", name=request.args.get("name"))
```

## Remediation Checklist

- [ ] Use parameterized queries / prepared statements for all database calls
- [ ] Use an ORM that handles escaping automatically
- [ ] Validate all input against a strict allowlist
- [ ] Use `shell=False` for all subprocess calls
- [ ] Use template engines correctly (pass variables, do not interpolate into template strings)
- [ ] Apply context-aware output encoding for web outputs
- [ ] Use LIMIT clauses to prevent mass data disclosure from SQLi
