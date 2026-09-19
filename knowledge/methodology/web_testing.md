# Methodology: Web Application Security Assessment

## 1. When to Use
Activate this methodology when the target is a browser-accessible web application, web frontend, or server-side rendered application (HTML/JS).

## 2. Key Hypotheses
- **H-WEB-01**: Missing or weak security transport and framing headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
- **H-WEB-02**: Session cookies lack critical security attributes (`Secure`, `HttpOnly`, `SameSite=Strict/Lax`).
- **H-WEB-03**: Hidden administrative routes or dev endpoints are exposed and indexed via `robots.txt` or wordlist fuzzing.
- **H-WEB-04**: Client-side parameter reflection without contextual sanitization leading to Cross-Site Scripting (XSS).
- **H-WEB-05**: Dynamic SQL query concatenation without parameterization leading to SQL Injection.

## 3. Recommended Tools
- `http_probe` / `send_http_request`: Baseline endpoint probing and header auditing.
- `cookie_audit`: Automated flag analysis on `Set-Cookie` directives.
- `dir_fuzz`: Directory and path discovery.
- `http_probe_batch`: Comparative anomaly detection on parameterized inputs.

## 4. Evidence Criteria
- **Header Findings**: Raw HTTP response headers showing absence of mandatory security policies.
- **Cookie Findings**: Raw `Set-Cookie` response headers missing `HttpOnly` or `Secure` flags.
- **Path Discovery**: Valid `200 OK` or `403 Forbidden` response confirming endpoint existence.
- **PoC Format**: Working `curl` command with exact headers and parameters (`curl_poc`).

## 5. Common False Positives
- WAF or CDN challenge pages (Cloudflare, Akamai) returning generic 200/403 responses.
- Static assets (images, CSS, fonts) missing security headers (only HTML/API responses require strict CSP/XFO).
- Development localhost bindings tested with `Secure` cookie flag missing (only flagged on HTTPS).
