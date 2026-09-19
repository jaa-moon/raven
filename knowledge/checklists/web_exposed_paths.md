# Sensitive path exposure checklist
Candidate paths: /.git/HEAD, /.env, /.env.production, /wp-config.php, /config.php, /actuator/env, /admin, /console, /phpinfo.php, /server-status, /swagger, /api-docs, /graphql, backup and archive files.
A candidate is only a finding if the response body has the content signature of that resource: git HEAD contains "ref: refs/heads/", dotenv has several KEY=VALUE lines, actuator returns JSON with status or propertySources. HTTP status alone proves nothing.
Always compare against a nonexistent route baseline first; single page applications answer every path with the same shell.

# Admin interface checklist
Distinct admin content, login form, admin-specific title, authentication state. A generic application shell is not an admin panel. Redirect to login means a protected interface exists, not that it is exposed.
