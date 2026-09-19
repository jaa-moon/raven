# REST API security checklist
Discover documentation: /openapi.json, /swagger.json, /api-docs, /v2/api-docs. Enumerate endpoints and methods, check authentication on every route, object level authorization, mass assignment, rate limiting, verbose errors.
API documentation exposure is a low severity information disclosure unless it reveals internal or undocumented endpoints.

# GraphQL security checklist
Introspection enabled in production, query depth and complexity limits, batching abuse, field level authorization, verbose error messages. GraphQL endpoint commonly at /graphql.
