# Flask Security Guide

## Overview

Flask is a lightweight WSGI web framework. Its minimal defaults mean developers
must explicitly add security controls. This guide covers the most critical
Flask-specific security issues Raven detects.

## 1. Secret Key Management

```python
# VULNERABLE — hardcoded secret key
app = Flask(__name__)
app.secret_key = "dev-secret-123"

# SAFE — loaded from environment
import os
app.secret_key = os.environ["FLASK_SECRET_KEY"]
# Generate a strong key: python -c "import secrets; print(secrets.token_hex(32))"
```

**Why it matters**: The secret key signs session cookies. A known key lets attackers
forge sessions and impersonate any user.

## 2. Debug Mode in Production

```python
# VULNERABLE — exposes interactive Werkzeug debugger
app.run(debug=True)

# SAFE — debug only in development, never in production
import os
app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
```

**Why it matters**: Werkzeug's debugger allows arbitrary Python code execution
from the browser with a PIN (or without one on older versions).

## 3. Server-Side Template Injection (SSTI)

```python
# VULNERABLE — user input in template string
from flask import render_template_string, request
name = request.args.get("name")
return render_template_string(f"Hello {name}!")
# Payload: ?name={{7*7}} renders "Hello 49!" — full RCE possible

# SAFE — use render_template with a file, pass variable separately
from flask import render_template
name = request.args.get("name", "")
return render_template("hello.html", name=name)
```

## 4. SQL Injection via SQLite/SQLAlchemy

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE id = {request.args.get('id')}"
db.execute(query)

# SAFE — use ORM or parameterized queries
user = User.query.filter_by(id=request.args.get("id")).first()
# or
db.execute("SELECT * FROM users WHERE id = :id", {"id": request.args.get("id")})
```

## 5. Security Headers

```python
# Install: pip install flask-talisman
from flask_talisman import Talisman
Talisman(app, content_security_policy={
    "default-src": "'self'",
    "script-src": "'self'",
})
# Adds: HSTS, X-Frame-Options, X-Content-Type-Options, CSP
```

## 6. CSRF Protection

```python
# Install: pip install flask-wtf
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
# All POST/PUT/DELETE forms now require a CSRF token
```

## Quick Checklist

- [ ] `SECRET_KEY` loaded from environment variable, not hardcoded
- [ ] `DEBUG=False` in production
- [ ] All database queries use parameterized statements or ORM
- [ ] Never use `render_template_string()` with user input
- [ ] Enable HTTPS (`SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`)
- [ ] Apply security headers with `flask-talisman`
- [ ] Enable CSRF protection with `flask-wtf`
