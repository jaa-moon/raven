# Lesson: single page application fallback
Context: SPA (Angular, React, Vue) served by Node or a static host.
Observation: unknown routes return index.html with HTTP 200, so /.env, /.git/HEAD and /admin all look "found".
Lesson: HTTP 200 alone does not establish that a route or file exists.
Recommended validation: compare each candidate response against a known nonexistent route baseline and inspect content signatures (dotenv key value lines, "ref: refs/heads", actuator JSON) before reporting.
