"""
Intentionally vulnerable Flask app — for Raven analysis testing only.
DO NOT deploy this code.
"""
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded secret key — bad practice
app.secret_key = "supersecretkey123"

# Hardcoded DB password — exposed credential
DB_PASSWORD = "admin123"

@app.route("/user")
def get_user():
    """SQL Injection vulnerability: user input inserted directly into query."""
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: raw string formatting — SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    return str(result)


@app.route("/ping")
def ping():
    """Command Injection vulnerability: user input passed to shell."""
    host = request.args.get("host", "localhost")
    # VULNERABLE: shell=True with user input — command injection
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output


@app.route("/template")
def template():
    """Server-Side Template Injection vulnerability."""
    name = request.args.get("name", "World")
    # VULNERABLE: user input rendered directly in Jinja2 template
    return render_template_string(f"<h1>Hello {name}!</h1>")


if __name__ == "__main__":
    # VULNERABLE: debug=True in production exposes the Werkzeug debugger
    app.run(debug=True, host="0.0.0.0")
