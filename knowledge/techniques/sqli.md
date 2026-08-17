# SQL Injection (SQLi) Attack Techniques

## Overview
SQL injection occurs when unvalidated user input is directly concatenated into SQL queries.

## Common Payloads
- `' OR '1'='1`
- `' UNION SELECT NULL, NULL, @@version--`
- `'; DROP TABLE users;--`

## Remediation
Use parameterized queries / prepared statements for all database operations.
