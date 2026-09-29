# Changelog

## Unreleased - Binary target file-permission auditing

The `permission_scan` tool already declared `binary` an in-scope target type and already supported a
single-file target, but no agent requested it for a binary, so the "File permissions" coverage surface
sat at `NOT_ASSESSED` for every binary assessment even though the check existed. This wires it up with no
new tool, dependency, or gateway change — the audit rides the existing capability/scope/budget/validation
path.

### Added
- **`agents/binary.py`**: `BinaryAssessmentAgent` now requests the `permission_audit` capability on the
  target binary's own path (new lowest-priority `perms` task and `_perms` step). A SUID/SGID or
  world-writable executable is a direct local-privilege-escalation surface; findings are raised only as
  candidates and independently re-audited by the existing `validation/checks_static.py::_v_file_permission`
  validator before they can be `CONFIRMED`. POSIX-only: on a non-POSIX host the gateway reports the tool
  unavailable (`requirements=["os:posix"]`) and the task is honestly `BLOCKED`, so the "File permissions"
  surface is `ASSESSED` on POSIX and `BLOCKED` elsewhere — never silently `NOT_ASSESSED`.
- **Tests** (`tests/integration/test_binary_assessment.py`): the full-assessment test now asserts the
  file-permission surface is wired (ASSESSED on POSIX / BLOCKED otherwise); a new POSIX-only test creates a
  `0o4755` SUID ELF and asserts the finding is raised and independently `CONFIRMED` with evidence.

## Unreleased - GraphQL input discovery v1 (query arguments, SQLi + SSRF)

Implements the GraphQL variable discovery previously investigated and deferred (see "Investigated,
deferred" below). Rides the existing active-injection pipeline unchanged: same gateway (scope/budget/
timeout), same evidence-aware `injection_surface`/`propose_tasks`/`_test` flow, same independent
re-validation in `validation/checks_injection.py`. No change to `raven_mcp/gateway.py`, `core/scope.py`,
`core/budget.py`, or `recovery/controller.py`.

### Added
- **Full-schema GraphQL introspection** (`agents/web_recon.py::_graphql_schema`, run automatically after
  the existing passive introspection check succeeds): a bounded-depth (4-level `ofType` unwrap) query
  fetching `queryType`/`mutationType` fields, each field's `args`, and every `INPUT_OBJECT` type's
  `inputFields` — previously the introspection query only ever requested type *names*.
- **`core/graphql_schema.py::parse_introspection`** (new, pure, unit-tested module): turns a raw
  introspection response into a bounded list of testable operations — for each query/mutation field, its
  top-level argument types, a safe baseline value for every argument (recursing into nested `INPUT_OBJECT`
  fields), and the dotted variable-path of every testable **scalar** leaf (`String`/`Int`/`Float`/`Boolean`/
  `ID`, top-level or nested). A `LIST`/`OBJECT`/`INTERFACE`/`UNION`/`ENUM`-typed argument is never treated as
  injectable; if it's required, the whole field is skipped (recorded as a limitation) rather than guessed
  at. Never raises on missing/incomplete/malformed introspection data — degrades to fewer operations.
- **`tools/injection_probe.py`**: `_place()` gained a `location="graphql"` mode that builds
  `{"query": "<document with variable declarations>", "variables": {...}}` (via new `_graphql_document`/
  `_set_graphql_variable` helpers) and POSTs it as `json=` (not form-encoded, unlike every other location);
  `_fetch()` gained a `json_body` parameter. `sql_probe`/`ssrf_probe` gained optional `operation_type`/
  `field`/`top_level_args`/`baseline_variables` kwargs, threaded through unchanged for every REST location.
  `xss_probe` and its tool schema were deliberately left untouched (see "Deferred" below).
- **`agents/injection.py`**: discovered GraphQL query-argument leaves are folded into the *same*
  `injection_surface` dict REST/HTML discovery populates (`location="graphql"`, `evidence="spec"`), via a
  new idempotent `_merge_graphql_operations`, called every planning pass so it works regardless of whether
  GraphQL introspection or this agent's own HTML-based discovery finishes first. `propose_tasks`/`_test`
  thread the extra GraphQL context through `task.params` into the capability call; SSRF hypotheses are now
  also proposed for a URL-like-named GraphQL scalar argument, using the identical loopback-callback
  mechanism (no new payload class).
- **`validation/checks_injection.py`**: `_v_sql_injection`/`_v_ssrf` now carry the same GraphQL context
  (`operation_type`/`field`/`top_level_args`/`baseline_variables`) from the candidate's `signal` into their
  own independent re-probe call, so a real GraphQL finding can reach `CONFIRMED` through the same two-
  independent-re-run repeatability requirement as REST — without this, `_place()` would have nothing to
  rebuild the GraphQL request from and every re-test would fail uniformly.
- **Tests**: 11 new unit tests for `core/graphql_schema.py` (correct discovery, list/enum/custom-scalar
  exclusion, nested multi-scalar input objects, malformed/incomplete-schema degradation), 4 new unit tests
  for the new `_place()`/`sql_probe` GraphQL request-building, and 10 new integration tests in
  `tests/integration/test_graphql_injection.py` against three new fixture-server variants in
  `tests/conftest.py` (introspection enabled with one genuinely vulnerable and one non-vulnerable field,
  introspection disabled, and malformed/incomplete introspection) — proving correct field/arg discovery with
  correct evidence tags, list-argument exclusion, mutation arguments discovered but never tested, a real
  SQLi signal reaching `CONFIRMED` via the same independent-revalidation path as REST, and both degraded
  cases producing an honest limitation with no crash and no fabricated surface. `tests/conftest.py`'s
  `_Server` now also reads the request body (needed for GraphQL's JSON POST envelope); all four existing
  route functions gained a `body` parameter (unused, backward compatible).

### Deferred (documented, not silently missing)
- **GraphQL mutation-argument testing.** Discovery parses mutation fields too (proven directly: a unit test
  finds all three nested scalar leaves of a `createUser(input: CreateUserInput!)`-shaped mutation), but
  `InjectionTestAgent` only folds `query` operations into `injection_surface`. Mutations write data, and
  building a confidently-safe, always-valid baseline for an arbitrary mutation's entire argument set (not
  just the variable under test) without a live target to validate against was judged too large a scope to
  rush into this milestone. The parsed mutation schema is retained
  (`profile.attributes["graphql_operations"]`) for a future round.
- **GraphQL XSS.** A GraphQL response is JSON, returned HTTP 200 even for a resolver error, and a reflected
  payload inside a JSON string is JSON-escaped, not HTML-escaped. The existing reflected-XSS heuristic
  (`core/injection_signals.py::xss_signals`, shared unchanged with REST/HTML — untouched by this round) partly
  decides "executable" by checking whether an injected `<` survives raw immediately before the marker, which
  it would in a JSON body (JSON escapes `"`/`\`/control characters, never `<`) — misclassifying an inert
  JSON-context reflection as executable HTML/JS. Rather than weaken or special-case that shared heuristic
  (used identically by independent validation) under time pressure, GraphQL XSS is scoped out entirely:
  no `injection.xss.reflect` task is ever emitted for a `location="graphql"` parameter.

## Unreleased - Binary Assessment Agent v1 (static only)

New capability where none existed: Raven could already classify a target as `binary` (ELF/PE/Mach-O
magic-byte detection in `tools/inventory.py::file_classify`) but had no agent for it — every binary target
reported `NOT_ASSESSED` across the board. Implemented independently in parallel with the GraphQL work
above; zero file overlap between the two (confirmed via `git diff --stat`), full suite green with both
present together.

### Added
- **`tools/binary_scanner.py`** (new, hand-rolled with `struct`, no new dependency): format/architecture
  identification (ELF class/endianness/`e_type`/`e_machine`; PE DOS→COFF `Machine` field; Mach-O
  header-level only), header-level hardening indicators (ELF NX-stack/RELRO-proxy/PIE-proxy; PE ASLR/DEP),
  ELF `DT_NEEDED` imported-library enumeration (real `PT_DYNAMIC`→`.dynstr` vaddr-to-file-offset
  resolution), and embedded printable-string extraction with secret/internal-host pattern matching and
  redaction (mirrors `tools/secret_scanner.py`'s masking convention — a matched value never leaves the tool
  unmasked).
- **`agents/binary.py::BinaryAssessmentAgent`** (new, registered in `agents/registry.py`): applies to
  `target_type == "binary"`; proposes format/hardening/imports/strings tasks, all through `ctx.call`
  (never a direct file-open outside a registered tool); raises CANDIDATE findings only, never
  self-confirms; records a limitation and marks the task `blocked` (not `done`) whenever a check can't run
  for the binary's actual format, rather than reporting a silent "checked, clean" result.
- **`validation/checks_binary.py::BinaryChecks`** (new, mixed into `validation/validator.py`): independently
  re-parses the binary fresh for every finding (never trusts the agent's claim) before confirming —
  identical discipline to every other finding type in this codebase.
- **`core/coverage.py`**: new `SurfaceSpec(name="Binary analysis", applies_to=BIN, ...)` with the exact
  static-vs-not-implemented scope baked into its `note` field. The pre-existing `Process & CLI` `SurfaceSpec`
  (anticipated for future dynamic/execution-based analysis) is untouched and confirmed, live, to render as
  `NOT_ASSESSED`.
- **Tests**: 20 new unit tests (`tests/unit/test_binary_scanner.py`) against synthetic, hand-built ELF/PE/
  Mach-O byte fixtures (`tests/fixtures_binary.py`, built with `struct.pack` — no real compiled binaries, no
  malware samples) covering correct identification, hardening detection (both present and missing), import
  enumeration, and graceful degradation on truncated/corrupt/unrecognized input; 5 new integration tests
  (`tests/integration/test_binary_assessment.py`) running a real `run_assessment()` against fixture files,
  proving `target_type` classification, coverage status (including `PARTIALLY_ASSESSED` for a PE binary
  where imports are unsupported), and independent-validation confirmation end to end.

### Deferred (documented, not silently missing)
- **PE import-table parsing.** Walking sections to the import directory RVA and resolving
  `IMAGE_IMPORT_DESCRIPTOR` entries was judged too large to implement and verify correctly with confidence
  in this pass. A PE binary's import task is honestly marked `blocked`, coverage becomes
  `PARTIALLY_ASSESSED`, never silently empty or clean.
- **Mach-O load-command parsing.** Identification stays header-level only (bits/endianness from the magic
  bytes); hardening and import checks report `supported: False` for Mach-O.
- **All dynamic/execution-based binary analysis.** The target binary is never run, mapped, or sandboxed in
  this milestone — no sandboxing infrastructure was built. The `Process & CLI` coverage surface remains
  `NOT_ASSESSED`.

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
