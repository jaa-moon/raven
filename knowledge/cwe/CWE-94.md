# CWE-94: Code Injection

## Description

Code Injection (CWE-94) occurs when an application evaluates attacker-controlled data
as code. Unlike OS Command Injection (CWE-78), this executes code within the application's
own runtime environment (e.g. Python interpreter, JavaScript engine).

## Risk

- **CVSS Score**: Up to 9.8 (Critical)
- **Impact**: Remote Code Execution within the application process, full server compromise
- **OWASP**: A03:2021 — Injection
- **Affected Languages**: Python (`eval`, `exec`), JavaScript (`eval`, `new Function`)

## Vulnerable Example (Python)

```python
# VULNERABLE: eval() with user-controlled input
user_formula = request.args.get("formula")
result = eval(user_formula)

# Attacker sends: formula=__import__('os').system('rm+-rf+/')
# Result: arbitrary OS command executed
```

## Vulnerable Example (JavaScript)

```javascript
// VULNERABLE: eval() with user input
const expression = req.query.expr;
const result = eval(expression);

// Attacker sends: expr=require('child_process').execSync('cat /etc/passwd')
```

## Safe Example (Python)

```python
# SAFE: use ast.literal_eval for safe evaluation of Python literals only
import ast
user_input = request.args.get("data")
result = ast.literal_eval(user_input)  # Only parses strings, numbers, lists, dicts, etc.

# SAFE: use explicit parsing for math expressions
import operator
# Use a dedicated math expression parser, NOT eval()
```

## Remediation

1. **Never use `eval()` or `exec()`** with external data.
2. Use `ast.literal_eval()` for parsing Python literals safely.
3. Use `JSON.parse()` for JSON data instead of `eval()` in JavaScript.
4. For mathematical expressions, use a sandboxed expression evaluator library.
5. Apply defense-in-depth: run the application in a container with resource limits.
