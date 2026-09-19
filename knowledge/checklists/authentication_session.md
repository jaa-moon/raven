# Authentication checklist
Inspect login mechanisms, WWW-Authenticate challenges, token types (JWT, session cookies), account lockout, password policy, default credentials, multi factor. Without credentials only passive review is possible; report the limitation.

# Session management checklist
Cookies should set HttpOnly, Secure (over TLS) and SameSite. Session identifiers must be unpredictable and rotated at login. Missing Secure over plain HTTP is a transport issue.

# JWT checklist
Verify signature algorithm handling (none, HS256 vs RS256 confusion), expiry enforcement, audience checks, key management, token storage location.
