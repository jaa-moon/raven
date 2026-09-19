# HTTP security headers checklist
Web application http headers: verify Strict-Transport-Security on HTTPS, Content-Security-Policy, X-Content-Type-Options nosniff, X-Frame-Options or CSP frame-ancestors, Referrer-Policy, Permissions-Policy.
A missing header is a hardening gap, not proof of exploitability. Re-fetch before reporting and check equivalent controls (CSP frame-ancestors replaces X-Frame-Options).

# Server information disclosure checklist
Check Server and X-Powered-By headers for version disclosure, verbose error pages, stack traces, debug modes. Record technologies to guide later testing.
