# Methodology: Authentication & Identity Security Assessment

## 1. When to Use
Activate this methodology when the target implements user authentication, bearer tokens, OAuth/OIDC, JWT signatures, session identifiers, or API keys.

## 2. Key Hypotheses
- **H-AUTH-01**: JWT 'none' algorithm bypass allows signature-less token acceptance.
- **H-AUTH-02**: JWT signature stripping accepts unverified tokens with stripped signature bytes.
- **H-AUTH-03**: Role escalation via unverified claims (`"role": "admin"`, `"is_superuser": true`).
- **H-AUTH-04**: Default developer credentials (e.g. `admin:admin`, `root:root`, `test:test`) accepted on login interfaces.
- **H-AUTH-05**: Lack of rate limiting on password reset or credential verification endpoints.

## 3. Recommended Tools
- `jwt_none_alg`: Automated algorithm 'none' token forgery testing.
- `jwt_empty_sig`: Signature stripping verification.
- `jwt_role_escalation`: Claim modification and privilege escalation checks.
- `default_creds_test`: Verification of common default credentials across HTTP and services.

## 4. Evidence Criteria
- **JWT Bypass**: Authenticated `200 OK` response or authorized resource access using a forged or stripped JWT token.
- **Default Creds**: Successful authentication response (HTTP 200/302, FTP 230, Redis PONG) with verified credential pair.
- **PoC Format**: Working reproduction steps with exact forged token or credentials.

## 5. Common False Positives
- Tokens validated by client-side JavaScript but rejected by backend API when executed.
- Mock authentication handlers returning synthetic responses in testing sandboxes.
- Endpoints that do not require authentication returning 200 OK regardless of token validity.
