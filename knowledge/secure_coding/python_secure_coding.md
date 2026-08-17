# Python Secure Coding Guide

## Overview

This guide covers the most critical Python-specific security patterns that
Raven's rule engine detects and the LLM analyzes.

## 1. Code Execution — eval() and exec()

```python
# VULNERABLE
user_input = request.args.get("formula")
result = eval(user_input)  # RCE if input is __import__('os').system('...')

# SAFE — use ast.literal_eval for literals
import ast
result = ast.literal_eval(user_input)  # Only parses literals, not code

# SAFE — use a proper expression parser for math
import numexpr  # or sympy — dedicated, sandboxed math evaluation
```

## 2. Subprocess — Command Injection

```python
# VULNERABLE
import subprocess
host = request.args.get("host")
subprocess.run(f"ping -c 1 {host}", shell=True)

# SAFE — list of args, shell=False
import subprocess, re
host = request.args.get("host", "")
if not re.match(r'^[a-zA-Z0-9.\-]+$', host):  # Whitelist
    raise ValueError("Invalid host")
subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5)
```

## 3. Deserialization — pickle

```python
# VULNERABLE
import pickle
data = request.data
obj = pickle.loads(data)  # Arbitrary code execution

# SAFE — use JSON
import json
obj = json.loads(request.data)

# SAFE — HMAC-signed pickle (if pickle is unavoidable)
import hmac, hashlib
SECRET = os.environ["SIGN_SECRET"].encode()
sig = hmac.new(SECRET, data, hashlib.sha256).digest()
assert hmac.compare_digest(sig, expected_sig), "Tampered!"
obj = pickle.loads(data)
```

## 4. SQL Injection

```python
# VULNERABLE — f-string interpolation
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SAFE — parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SAFE — SQLAlchemy ORM
user = session.query(User).filter(User.id == user_id).first()
```

## 5. Path Traversal

```python
# VULNERABLE
filename = request.args.get("file")
with open(f"/app/data/{filename}") as f:  # ../../../etc/passwd
    return f.read()

# SAFE — resolve and validate
from pathlib import Path
base = Path("/app/data").resolve()
target = (base / filename).resolve()
if not str(target).startswith(str(base)):
    raise PermissionError("Path traversal detected")
with open(target) as f:
    return f.read()
```

## 6. Secrets Management

```python
# VULNERABLE
DB_PASSWORD = "admin123"

# SAFE
import os
from dotenv import load_dotenv
load_dotenv()
DB_PASSWORD = os.environ["DB_PASSWORD"]
```

## Security Checklist

- [ ] Never use `eval()` or `exec()` with external data
- [ ] Always use `shell=False` in subprocess calls
- [ ] Never deserialize pickle from untrusted sources
- [ ] Use parameterized queries for all database access
- [ ] Validate and sanitize all file paths
- [ ] Store all secrets in environment variables
- [ ] Use `secrets` module for cryptographic randomness (not `random`)
