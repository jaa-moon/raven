# Auth Server Tools
Provides tools for attacking authentication mechanisms and session management.

## jwt_attack
Attempts JWT signature stripping and 'none' algorithm bypass on an endpoint. Provide a valid sample JWT token to use as a baseline.

## session_test
Analyzes session cookie generation and entropy by observing how the application assigns session identifiers.

## cookie_audit
Audits cookie security flags, such as HttpOnly, Secure, and SameSite attributes.
