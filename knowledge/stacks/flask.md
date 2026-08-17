# Flask Pentesting Guide

## Key Surface Areas
- Route definitions via `@app.route`
- Request parameter access via `request.args.get()`, `request.form.get()`
- Debug mode enabled (`app.run(debug=True)`) exposing Werkzeug interactive debugger
- Secret key configuration `app.config['SECRET_KEY']` for session tamper resistance

## Common Vulnerabilities
- Raw string interpolation in SQLite queries
- SSTI (Server-Side Template Injection) via `render_template_string(user_input)`
