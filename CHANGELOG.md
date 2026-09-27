# Changelog

## Unreleased - Release stabilization: budget-conflation fix, test coverage gaps closed

### Fixed
- **Budget-dimension conflation could silently skip unrelated test coverage.**
  `BudgetManager.used_fraction()` took the max across all five independent budget dimensions
  (tool_calls, seconds, iterations, llm_calls, expensive_ops). Because `max_expensive_ops`
  defaults to 6 and both SQLi and SSRF probes are flagged `expensive`, a handful of injection
  tests could exhaust that one narrow dimension and, via `BUDGET_FLOOR["exhausted"] = 101`,
  cause the planner to skip *all* remaining pending tasks — including cheap, unrelated ones —
  even with most of the tool-call and time budget still unused. `used_fraction()` now only
  considers tool_calls/seconds/iterations, the genuinely global "runway" dimensions;
  expensive_ops/llm_calls remain correctly enforced per-call via
  `can_afford(expensive=...)`/`can_afford(llm=...)` in the gateway, unchanged.
- **Misleading CLI error for an unsupported URL scheme.** `raven assess "nonexistent://x"`
  reported "Invalid port in target" (it fell through to the bare `host:port` parser). Now
  reports "Unsupported URL scheme 'nonexistent' — only http:// and https:// are supported."
  Still exits cleanly with code 1 in both cases.

### Added (test coverage, no behavior change)
- End-to-end fixture-server coverage for admin-panel/actuator/config-file exposure confirmation
  (previously only unit-tested directly against the `validation/content.py` functions, never
  through the full agent → gateway → validator → independent-revalidation → report pipeline).
- Unit tests for `tools/permission_scanner.py` (previously zero coverage): SUID and
  world-writable detection via a mocked `Path.stat()`, plus a negative/no-false-positives case.

### Investigated, deferred (no code change)
- **GraphQL variable discovery.** Confirmed this needs a larger introspection query (current one
  only requests type names, never `args`/`fields`) and a new request-placement mode in
  `tools/injection_probe.py` (existing modes can't express GraphQL's JSON `query`+`variables`
  envelope) — a multi-part feature, not a short wiring change. Left for a future milestone.

## Unreleased - Input Surface Discovery v2 and evidence-aware active-testing prioritization

Addresses the two gaps identified after the first live active-injection run: discovery was narrowly
centered on the discovered `id` query parameter, and the planner had no way to prefer high-value active
tests over low-value generic breadth tasks once the budget tightened. No change to scope/budget/gateway
enforcement or to independent validation.

### Added
- **REST path parameters**: a trailing numeric, UUID, or Mongo-ObjectId-like path segment — on a link on
  the fetched page or on any endpoint already known from other agents — is now discovered and tested as a
  path parameter (e.g. `/api/Widgets/7`), not just query-string `id`s. `tools/injection_probe._place` gained
  a `location="path"` substitution that replaces exactly that literal segment.
- **Cookies**: names from the target's own `Set-Cookie` responses are discovered as input surface (excluding
  known third-party/analytics cookies), since session/state cookies are a common injection vector.
- **OpenAPI/Swagger spec parsing**: when a spec is published at a known path (`/openapi.json`,
  `/swagger.json`, `/api-docs`, `/v2/api-docs`), Raven now parses it for real query, path, and JSON-body
  parameter names — the only way to learn request-body fields without executing client-side JavaScript, and
  the strongest evidence tier discovery has.
- Every discovered parameter now carries an **evidence tag** (`spec` / `form` / `cookie` / `observed` /
  `guessed`) recording how it was found, surfaced in each task's rationale.

### Changed
- **Task priority is now evidence-aware** (`agents/injection.py::_task_priority`) instead of a fixed
  per-injection-type constant: it combines a base score per injection class, a bonus for stronger evidence
  (a spec definition or real form field outranks a bare naming-convention guess), and a bonus when the
  endpoint or parameter name looks security-sensitive (login/auth/admin/password/token/...). This is a
  scoring mechanism, not a hardcoded priority list, so under a tight budget the planner now spends active-
  testing budget on the parameters most likely to matter instead of treating every discovered `id` the same.
- SSRF hypotheses are only proposed for `query`/`body` locations (a path segment or cookie name is never
  itself a plausible server-fetched URL).

### Still not implemented (honest gap)
- Blind/arbitrary header fuzzing (e.g. `X-Forwarded-Host`) and JSON body fields with neither a spec nor a
  form to evidence them remain out of scope — Raven still never guesses input surface it hasn't observed.
- **GraphQL variables** are still not fed into active injection testing at all. `WebReconAgent` only runs a
  passive introspection check (`GraphQLIntrospectionEnabled`); `InjectionTestAgent` never builds an
  `injection_surface` entry from a GraphQL schema or query, so SQLi/XSS/SSRF on GraphQL arguments is
  untested and reported as `NOT_ASSESSED`, never as clean.

## Unreleased - Risk level made user-configurable

Exposed the existing (already-enforced) assessment risk control through the normal user-facing flow.
No change to the security model: ScopeValidator, BudgetManager and the Gateway remain authoritative.

### Added
- **Interactive menu risk selection**: the Test flow now prompts for Low / Moderate / High, shows the full
  configuration (target, type, depth, risk, budget) before the run, and warns when active testing is enabled.
  The menu and the `--max-risk` CLI flag funnel into the same `run_assessment(max_risk=...)` path — one source
  of truth (`Scope.max_risk`), no parallel risk values.
- `--max-risk` on the `pentest` alias (already present on `assess`/`scan`); the flag is now validated against
  `passive|low|moderate|high`.
- The report header now records the selected **Risk level** and whether active injection testing was enabled.
- When `high` is selected but no high-risk capabilities exist, the run records an explicit limitation rather
  than implying extra testing happened.

### Changed
- Coverage for SQL Injection / XSS / SSRF now gives an explicit NOT_ASSESSED reason — "blocked by risk policy"
  or "no eligible input surface discovered" — instead of a generic "no test was planned", so an unassessed
  surface is never mistaken for "not vulnerable".

## Unreleased - Active Injection Testing hardening

Strengthened Active Injection Testing v1 without changing Raven's architecture or safety guarantees
(scope/budget/gateway/independent-validation all preserved).

### Changed
- **SQL injection** now sends two benign baselines to measure the response's natural byte-length jitter,
  and confirms boolean-based injection only when the true/false divergence exceeds that jitter *and* the
  two branches differ from each other. A database-error signature counts only when it is absent from the
  baseline. A bare 500, a length change, or a timing difference is still never proof on its own.
- **XSS** detection now checks that an injected metacharacter actually breaks out at the reflection site
  (`tag_breakout`) rather than treating mere marker presence as executable; partially-escaped reflections
  are correctly rejected as reflection, not XSS.
- **SSRF** distinguishes "callback mechanism unavailable" from "callback not observed", so an unbindable
  loopback listener is reported as untested, never as absence of the vulnerability.
- **Input-surface discovery** now handles action-less forms (submitting to the current page), `<textarea>`
  /`<select>` names, and query strings on already-discovered endpoints — no new crawler.
- Candidate/validator signal math is unified in `core/injection_signals.py`, so the threshold used to raise
  a candidate can no longer drift from the one used to confirm it.

### Fixed
- Raw HTTP response bodies are no longer persisted in a candidate's stored signal or hypothesis trail; only
  redacted per-test metrics (status, length, error-signature) are kept.

## 3.1.0 - Adaptive engine rebuild

Complete rework around a target-agnostic, adaptive architecture (see README).

### Added
- Target intake/analysis producing a `TargetProfile`; scope derived from the target.
- Capability-based tool registry + MCP gateway (arg validation, scope, budget, timeout, normalization).
- Adaptive planner (re-plans every iteration; budget-aware; bounded optional LLM prioritization).
- Independent validator with SPA/route baselines, content signatures and secret redaction.
- Recovery controller with recorded decisions; honest coverage (`ASSESSED/PARTIALLY_ASSESSED/NOT_ASSESSED/NOT_APPLICABLE/BLOCKED`).
- Contextual knowledge (checklists, cases, validated lessons) and a learning pipeline gated on validated evidence.
- Simple menu CLI (Test / Setup / Help / Version / Exit); `--yes` for non-interactive authorization.

### Removed
- Legacy engine, engine models, capability manifests, adapters, orchestrator, sandbox, old reports/RAG (FAISS),
  readers, MCP subprocess servers, parallel web-scanner pipeline, unused tools (fuzzers, credential tester,
  process prober, external runners), PR-comment/badge CI helpers, and their tests.

### Fixed (defects in the previous engine, removed with it)
- Specialized agents were never executed (planner/agent identifier mismatch); tool calls used wrong parameter
  names/result shapes; every agent self-confirmed its findings; empty scans were scored "Clean";
  coverage marked unexecuted tests as tested; scope allowed every domain by default.


All notable changes to Raven will be documented in this file.

## [3.0.0] - 2026-09-16
### Added
- **Universal Target Resolution**: The new `TargetResolver` identifies targets dynamically (Web Apps, REST APIs, network services, binaries, repositories).
- **Deterministic Agent Routing**: `PlanningAgent` dynamically routes tasks to 7 specialized agents (e.g., `BinaryAssessmentAgent`, `NetworkAssessmentAgent`, `WebApiAgent`).
- **7 New Native MCP Tools**: The tool gateway expanded with `cli_fuzzer`, `protocol_prober`, `process_prober`, `banner_grabber`, `default_creds_tester`, `config_scanner`, and `permission_scanner`.
- **ValidationAgent**: Strict verification for all findings. Mandates reproducible `curl_poc` or `cli_poc`.
- **Honest Reporting**: Output reports explicitly disclose untested boundaries due to rate-limits or scope restrictions, avoiding false "no vulnerabilities found" claims.
- **RAG Memory Injection**: Integrates memory hints dynamically prior to the planning phase based on target profiles.
- **Atomic State Persistence**: Robust pause, resume, and crash recovery.
