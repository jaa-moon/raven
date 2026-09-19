# Case: Node.js Express REST API with JWT
Target technology: Node.js and Express. Surface: REST API with JWT authentication.
Previous observation: bearer tokens issued at login, API routes under /api and /rest.
Investigation that worked: locate token issuing endpoint, check algorithm handling and expiry, then test authorization boundaries between users.
