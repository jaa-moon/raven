# Methodology: REST & GraphQL API Security Assessment

## 1. When to Use
Activate this methodology when the target exposes RESTful HTTP endpoints, JSON/XML APIs, microservice interfaces, or GraphQL schemas (`/graphql`, `/api/v1`, `/v2`).

## 2. Key Hypotheses
- **H-API-01**: Permissive or misconfigured CORS (`Access-Control-Allow-Origin: *` with credentials).
- **H-API-02**: Broken Object Level Authorization (BOLA / IDOR) allowing unauthorized record retrieval across tenant boundaries.
- **H-API-03**: Verb tampering / Method override (`GET` vs `POST` vs `DELETE` vs `PUT`) bypassing access controls.
- **H-API-04**: Excessive data exposure in JSON payloads (internal user metadata, database IDs, password hashes).
- **H-API-05**: Introspection enabled in production GraphQL schemas exposing sensitive mutations and query trees.

## 3. Recommended Tools
- `http_probe`: Query parameter probing, custom method invocation, and payload delivery.
- `http_probe_batch`: Batch probing for integer/UUID IDOR sweeps and fuzzing.
- `cookie_audit`: Token and header session management checks.

## 4. Evidence Criteria
- **BOLA / IDOR**: Differential HTTP responses showing unauthorized object access with differing user identifiers.
- **CORS Misconfiguration**: Response reflecting `Access-Control-Allow-Origin: https://attacker.com` with `Access-Control-Allow-Credentials: true`.
- **GraphQL Introspection**: Response containing full `__schema` JSON metadata.
- **PoC Format**: Working `curl` command with sample request and response payloads.

## 5. Common False Positives
- Public or read-only APIs that intentionally allow wildcard CORS without credentials.
- Publicly accessible resource IDs where no authorization boundary is violated.
- API documentation endpoints (`/swagger`, `/openapi.json`) intended for public consumption.
