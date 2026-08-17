# OWASP A02:2021 — Cryptographic Failures

## Description

Cryptographic Failures (formerly "Sensitive Data Exposure") covers failures related
to cryptography that often lead to exposure of sensitive data. This includes using
weak or broken cryptographic algorithms, hardcoding secrets, transmitting data in
cleartext, or improper key management.

## Risk

- **CVSS Range**: 5.0 – 9.8
- **Impact**: Exposure of passwords, credit cards, health records, PII; account takeover
- **CWE Coverage**: CWE-259, CWE-321, CWE-326, CWE-327, CWE-330, CWE-798

## Common Vulnerable Patterns

### Hardcoded Secrets
```python
# VULNERABLE
SECRET_KEY = "mysecretkey"
API_TOKEN = "Bearer abc123xyz"

# SAFE
import os
SECRET_KEY = os.environ["SECRET_KEY"]
```

### Weak Hashing (MD5/SHA1 for passwords)
```python
# VULNERABLE — MD5 is cryptographically broken
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# SAFE — use bcrypt or argon2 with salt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### HTTP instead of HTTPS
```python
# VULNERABLE
requests.get("http://api.example.com/sensitive-data")

# SAFE
requests.get("https://api.example.com/sensitive-data", verify=True)
```

## Remediation Checklist

- [ ] Remove all hardcoded passwords, API keys, and tokens
- [ ] Use environment variables or secrets managers for all credentials
- [ ] Use strong, modern password hashing: `bcrypt`, `argon2`, or `scrypt`
- [ ] Enforce TLS 1.2+ for all data in transit
- [ ] Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption
- [ ] Rotate keys regularly and have a key revocation procedure
- [ ] Never log sensitive data (passwords, tokens, SSNs)
