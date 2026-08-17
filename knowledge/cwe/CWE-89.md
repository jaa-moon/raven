# CWE-89: SQL Injection

## Description

SQL Injection (CWE-89) occurs when user-supplied data is incorporated into an SQL query
without proper neutralization. This allows attackers to manipulate the query's logic,
bypass authentication, read sensitive data, modify or delete database records, or
in some configurations, execute OS commands.

## Risk

- **CVSS Score**: Up to 9.8 (Critical)
- **Impact**: Authentication bypass, full database exfiltration, data modification, RCE
- **OWASP**: A03:2021 — Injection
- **Affected Languages**: Python, JavaScript, PHP, Java, Go, Ruby

## Vulnerable Example (Python)

```python
# VULNERABLE: f-string SQL — direct user input interpolation
username = request.form["username"]
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# Attacker sends: username = ' OR '1'='1
# Result: query becomes SELECT * FROM users WHERE username = '' OR '1'='1'
# All users returned — authentication bypassed
```

## Vulnerable Example (Python — concatenation)

```python
# VULNERABLE: string concatenation
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
```

## Safe Example (Python)

```python
# SAFE: parameterized query — user data never touches the SQL string
username = request.form["username"]
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# SAFE: using SQLAlchemy ORM
user = session.query(User).filter(User.username == username).first()
```

## Remediation

1. **Always use parameterized queries** (also called prepared statements).
2. Use an ORM (SQLAlchemy, Django ORM, GORM) that handles parameterization automatically.
3. Apply input validation — whitelist expected character sets.
4. Implement least-privilege database accounts (no DROP/DELETE unless necessary).
5. Enable database query logging and alerting for anomalous patterns.
