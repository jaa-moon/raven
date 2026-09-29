# Raven — Project Status & Changes Report

**Date:** 2026-09-29
**Branch:** `master`
**Working tree:** clean (after the release-hardening commit)
**Version line:** 5.0.0 (first public release; adaptive engine)
**Release status:** **Ready for first public GitHub release.** Verified on this baseline: full suite
259 passed / 1 skipped; benchmark 12/13 pass + 1 POSIX-only skip, 0 unexpected confirmations; clean
`pip install` in a fresh venv runs `version`/`--help`/`scan` end to end with a usable, redacted report
and no LLM required. No GitHub remote is configured yet — see §5 for the exact publish commands.

---

## 1. Current stage

Raven is at the **v3.1 "adaptive assessment engine"** stage: a target-agnostic security
assessment platform that observes a target, works out what it is, plans capability-based tests,
runs them through a scoped and budgeted gateway, **independently validates** every candidate
finding, and reports honest coverage. It never treats "no findings" as "secure".

Core loop: `observe → understand → plan → act → observe → update context → re-plan`.

Test suite: **259 passing, 1 skipped** (unit + integration against real local servers + regression;
the single skip is the POSIX-only SUID file-permission test, skipped on non-POSIX hosts). The V5 round
added the binary permission fix, planner-contract regression tests, and 15 benchmark self-tests — see §2.
Separately, `python -m benchmark` runs 13 controlled end-to-end assessment scenarios (12 + 1 POSIX-only).

---

## 2. Recent changes

Most recent commits (newest first):

| Commit | Change |
|---|---|
| *(this round)* | **Release stabilization** — see below |
| `9ab722f8` | Fix silent partial-failure masking in `WebExposureAgent`; add `config_scanner` tests |
| `177df522` | Fix: CLI crashed with a raw traceback on a corrupt/incompatible `--resume` state file |
| `85375094` | Harden active injection testing; add Input Surface Discovery v2 (REST path params, cookies, OpenAPI/Swagger parsing, evidence-aware task priority) |
| `6320c82` | **Active Injection Testing v1** — controlled SQLi / XSS / SSRF probing |
| `518c520` | **Rebuild** as a target-agnostic adaptive assessment engine (v3.1) |
| `4732e4f` | SPA-fallback detection and evidence-based path validation |
| `09a760c` | Checkpoint before the rebuild |

### This round: final stabilization, bug fixes, and launch readiness
Verified the current repository and test baseline directly (not prior audit summaries) and fixed
what was actually confirmed, in priority order:
- **Admin-panel / actuator / config-file confirmation had no end-to-end fixture coverage.** The
  validators in `validation/content.py` were already correct and unit-tested directly, but no
  fixture server exercised the full agent → gateway → validator → independent-revalidation →
  report pipeline for these three categories. Added an `admin_leaky_server` fixture
  (`tests/conftest.py`) with genuine exposures plus 404 siblings in the same probe groups, and an
  integration test asserting all three are CONFIRMED and none of the siblings are.
- **`tools/permission_scanner.py` had zero test coverage anywhere.** Added unit tests for SUID and
  world-writable detection using a mocked `Path.stat()` (Windows synthesizes its own st_mode where
  every file reports world-writable, so real files can't test this — the mock builds a controlled
  POSIX mode instead) plus a negative/ordinary-permissions case. Confirmed, live, that the
  `permission_audit` capability is correctly gated off entirely on non-POSIX systems
  (`tools/catalog.py` `requirements=["os:posix"]`) and that a real run against this Windows
  machine honestly reports the "File permissions" surface as `BLOCKED` with a clear reason, never
  as clean.
- **Budget-dimension conflation silently gutted test coverage on ordinary runs (P1).** `BudgetManager.used_fraction()` took the max across *all five* independent budget dimensions
  (tool_calls, seconds, iterations, llm_calls, expensive_ops). Since `max_expensive_ops` defaults
  to 6 and both SQLi and SSRF probes are flagged `expensive`, a handful of injection tests could
  push that one narrow dimension to "exhausted" and — via `BUDGET_FLOOR["exhausted"] = 101` —
  silently skip *all* remaining pending tasks, including cheap, unrelated ones, while tool-call and
  time budget sat mostly unused. Reproduced live (48/120 tool calls, <1s/900s elapsed, but
  `expensive_ops=6/6` skipped every XSS and SSRF task). Fixed by excluding `expensive_ops`/
  `llm_calls` from the global floor-gating signal — they're already correctly and independently
  enforced per-call by `can_afford(expensive=...)`/`can_afford(llm=...)` in the gateway, which is
  unchanged. Regression tests added at both the `BudgetManager` and `Planner` level.
- **Misleading CLI error for an unsupported URL scheme (P2).** `nonexistent://bad-target` fell
  through to the bare `host:port` parser and reported "Invalid port" instead of naming the actual
  problem. `core/target.py::parse_target` now recognizes any `scheme://` input and reports the
  unsupported scheme by name before it can reach that branch. Still exits cleanly (code 1), no
  traceback, in either case — this only improves the message.
- **GraphQL input discovery v1 — implemented (query arguments, SQLi + SSRF only).** A prior round
  investigated this and deferred it (confirmed as a genuine multi-part change: a richer
  introspection query, a new request-placement mode, and safe changes to the shared discovery/
  testing pipeline, not a short wiring fix). Now built end-to-end. See "What GraphQL Input
  Discovery v1 added" further down for the full scope, including what is *still* deliberately out
  — mutation-argument testing and GraphQL XSS remain explicit, documented gaps, not silently
  missing.
- **Binary Assessment Agent v1 (static only) — implemented.** Raven previously classified a target
  as `binary` (`intelligence/target_analyzer.py`, via `file_classify`'s ELF/PE/Mach-O magic-byte
  detection) but had no agent for it at all — every binary target reported `NOT_ASSESSED` across
  the board. New `BinaryAssessmentAgent` (`agents/binary.py`) adds format/architecture
  identification, header-level hardening indicators, ELF imported-library enumeration, and
  embedded-string/secret inspection — see "What Binary Assessment Agent v1 added" further down for
  full scope and what remains deliberately unimplemented (PE imports, Mach-O internals, and all
  dynamic/execution-based analysis — the binary is never run).

### What the rebuild (`518c520`) delivered
- Target intake/analysis producing a `TargetProfile`; scope derived from the target itself.
- Capability-based tool registry + MCP gateway (arg validation, scope, budget, timeout, normalization, logging).
- Adaptive planner that re-plans every iteration, is budget-aware, and uses an **optional** LLM only for bounded prioritization (it can never override scope, budget, tool schemas, or validation).
- Independent validator with SPA/route baselines, content signatures, and secret redaction.
- Recovery controller with recorded decisions and honest coverage states (`ASSESSED / PARTIALLY_ASSESSED / NOT_ASSESSED / NOT_APPLICABLE / BLOCKED`).
- Removed the legacy engine and its known defects (agents that never executed, self-confirming findings, empty scans scored "Clean", scope allowing every domain by default).

### What Active Injection Testing v1 (`6320c82`) added
- `InjectionTestAgent` discovers real input surface (forms, query-string parameters, the REST `id` convention) and requests `injection.sql.detect` / `injection.xss.reflect` / `injection.ssrf.detect` through the same gateway path as every other capability.
- Agents only raise **candidates**; `validation/checks_injection.py` independently re-probes and requires the behavior to repeat before confirming.
- Payloads are **non-destructive**: boolean/error-based SQL probes (no writes), a single reflected canary marker for XSS (escaped reflection rejected), and SSRF detection via a Raven-hosted loopback callback rather than an arbitrary external host.
- **Gated by scope:** active probing only runs at `--max-risk moderate` or higher; below that it is recorded as an explicit limitation, never silently skipped, and no active request is attempted.

### What Input Surface Discovery v2 + evidence-aware prioritization added (uncommitted)
Follow-up to the first live run against a real target, which showed discovery narrowly centered on
query-string `id`s and active-testing budget being crowded out by low-value generic breadth tasks.
- **Broader input surface**: REST path parameters (a numeric/UUID/ObjectId-like path segment, e.g.
  `/api/Widgets/7`), cookies set by the target (excluding known analytics/third-party cookies), and — when
  the target publishes one — an OpenAPI/Swagger spec parsed for real query, path, and JSON-body parameter
  names. `tools/injection_probe._place` gained a `location="path"` substitution.
- **Evidence tags, not bare names**: every discovered parameter records *how* it was found (`spec` / `form`
  / `cookie` / `observed` / `guessed`).
- **Evidence-aware task priority** (`agents/injection.py::_task_priority`): a scoring function — base score
  per injection class, plus a bonus for stronger evidence, plus a bonus for security-sensitive endpoints/
  parameter names (login/auth/admin/token/...) — replaces the previous fixed per-type priority constant, so
  a tight budget is spent on the parameters most likely to matter rather than treating every discovered `id`
  identically. This is a mechanism, not a hardcoded ordered list.
- Still not implemented: blind/arbitrary header fuzzing, and JSON body fields with neither a spec nor a form
  to evidence them — Raven still never tests input surface it hasn't actually observed.

### What GraphQL Input Discovery v1 (uncommitted) added
Closes the GraphQL gap called out above and in the two preceding rounds' notes. `WebReconAgent._graphql()`
still runs its original cheap passive check first (unchanged, same candidate); when introspection is
enabled it now additionally fetches a **bounded-depth (4-level) full introspection query** — `queryType`/
`mutationType`, and every type's `fields{args}` / `inputFields`, each argument's type resolved through up to
three `ofType` unwraps — and hands the parsed JSON to a new, pure, unit-tested module,
`core/graphql_schema.py::parse_introspection`, which never raises and degrades to fewer (never fabricated)
operations on any incomplete/malformed response.
- **Scalar leaves only, never guessed.** Only `String`/`Int`/`Float`/`Boolean`/`ID` arguments — top-level or
  nested one-or-more levels inside an `INPUT_OBJECT` — are ever treated as testable. A `LIST` or
  `OBJECT`/`INTERFACE`/`UNION`/`ENUM`-typed argument is never injected into as a single string value; an
  optional one is safely omitted, a **required** one makes that whole field's request unbuildable with
  confidence, so the field is skipped (recorded, via `state.add_limitation`) rather than guessed at.
- **Vary one variable, default every sibling.** For each testable leaf, Raven also records the GraphQL type
  declaration and a safe baseline value for *every other* argument/field on the same operation (built
  recursively for nested input objects), the same "vary one field, default the rest" principle REST form/
  body testing already used. `InjectionTestAgent` folds these into the *same* `injection_surface` dict REST/
  HTML discovery populates (`location="graphql"`, `evidence="spec"` — introspection is ground truth, same
  tier as an OpenAPI/Swagger spec), so GraphQL arguments flow through the identical
  propose_tasks → capability call → Gateway (scope+budget, unchanged) → probe → independent-revalidation
  pipeline as every other parameter, with zero new bypass path. `tools/injection_probe.py::_place()` gained
  a `location="graphql"` mode that builds `{"query": "<document with variable declarations>", "variables":
  {...}}` and POSTs it as `json=` (not form-encoded); `_fetch()` gained a `json_body` parameter to send it.
- **Query arguments only — mutation-argument testing is a deliberate, documented gap.** Discovery *parses*
  both `queryType` and `mutationType` fields (proven by a unit test finding all three nested scalar leaves of
  a `createUser(input: CreateUserInput!)`-shaped mutation), but `InjectionTestAgent` only folds `query`
  operations into `injection_surface` — mutation arguments are found, never actively tested. Mutations write
  data, and confidently building a safe, always-valid baseline for an arbitrary mutation's *entire* argument
  set (not just the one under test) without a live target to validate against was judged too large a scope
  to rush into this milestone with confidence; the discovered mutation schema is retained
  (`profile.attributes["graphql_operations"]`) for a future round to build on.
- **XSS on GraphQL arguments is deliberately deferred, not implemented.** A GraphQL response is JSON,
  returned with HTTP 200 even for a resolver error, and a reflected payload inside a JSON string is
  JSON-escaped, not HTML-escaped. The existing reflected-XSS heuristic
  (`core/injection_signals.py::xss_signals`, shared unchanged with REST/HTML testing) decides "executable"
  partly by checking whether an injected `<` survives raw immediately before the marker — which it would in
  a JSON body (JSON only escapes `"`/`\`/control characters, never `<`), misclassifying an inert JSON-context
  reflection as executable HTML/JS. Rather than weaken or special-case that shared heuristic (used
  identically by independent validation) under time pressure, GraphQL XSS testing is scoped out entirely:
  `propose_tasks` never emits an `injection.xss.reflect` task for a `location="graphql"` parameter, and
  `xss_probe`'s tool schema was deliberately left untouched (no GraphQL kwargs at all) so this can't
  silently regress.
- **SSRF is in scope, using the identical loopback-callback mechanism** (no new payload class); a
  `String`-typed GraphQL argument whose name looks like a URL/destination gets an SSRF hypothesis exactly
  like a REST query/body parameter would.
- Introspection-disabled and malformed/incomplete-introspection responses both degrade honestly: a limitation
  is recorded, no GraphQL surface is fabricated, and the assessment completes without crashing (fixture-server
  integration-tested for both).

### What Binary Assessment Agent v1 (uncommitted) added
All parsing is hand-rolled with `struct` in `tools/binary_scanner.py` — no new dependency — and every finding
is independently re-validated by fresh re-parsing (`validation/checks_binary.py`), never trusting the agent's
own claim, exactly like every other finding type in this codebase.
- **Format/architecture ID.** ELF (class, endianness, `e_type`, `e_machine` mapped for x86/x86-64/ARM/
  AArch64/RISC-V/etc.) and PE (DOS→COFF `Machine` field, mapped for x86/x64/ARM/ARM64/IA-64) get full
  identification; Mach-O is header-level only (bits/endianness from the magic bytes already in
  `tools/inventory.py::file_classify`) — deeper Mach-O load-command parsing was not attempted.
- **Hardening indicators.** ELF: NX-stack (`PT_GNU_STACK` exec bit), a RELRO proxy (none/partial/full via
  `PT_GNU_RELRO` + `DT_BIND_NOW`/`DT_FLAGS`/`DT_FLAGS_1`), and a PIE proxy (`e_type == ET_DYN` vs `ET_EXEC`).
  PE: ASLR (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`) and DEP (`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`) bits from
  `DllCharacteristics`. A missing property raises a CANDIDATE finding, never self-confirmed.
- **ELF imports fully implemented** (`DT_NEEDED` entries via real `PT_DYNAMIC`→`.dynstr` vaddr-to-file-offset
  resolution). **PE import-table parsing was explicitly not attempted** this round — walking sections to the
  import directory RVA and resolving `IMAGE_IMPORT_DESCRIPTOR` entries was judged too large to implement and
  verify correctly with confidence in this pass; a PE binary's import task is honestly marked `blocked`, not
  silently empty.
- **Embedded strings.** Printable-ASCII runs (capped read size and match count) are scanned for
  secret-shaped patterns (AWS keys, JWTs, GitHub/Slack tokens, private-key headers, generic API-key literals)
  and internal-host/IP references, using the same redact-before-it-leaves-the-tool convention as
  `tools/secret_scanner.py` — a matched value never appears in a finding's evidence unmasked. Dangerous
  function-name references (`system`, `strcpy`, ...) are recorded as an informational observation only, not a
  finding, to avoid noise.
- **No execution, ever, in this milestone.** The binary is never run, mapped, or sandboxed — dynamic/
  execution-based analysis (the pre-existing `Process & CLI` coverage surface) stays `NOT_ASSESSED`, verified
  live to render that way, never as clean.
- Truncated/corrupt headers and unrecognized formats all degrade to a recorded limitation and a `blocked`
  task (never a crash, never a false "checked, clean" result) — unit-tested directly against synthetic,
  hand-built byte fixtures (`tests/fixtures_binary.py`; no real compiled binaries, no malware samples).

### What the V5 round added (`9a299542`, `2a4235cb`, benchmark)

- **Binary file-permission auditing (`9a299542`).** `BinaryAssessmentAgent` now requests the existing
  `permission_audit` capability on the target binary's own path (SUID/SGID, world-writable — a direct
  local-privilege-escalation surface), independently re-validated by the existing `file_permission`
  validator. Previously the "File permissions" surface sat at `NOT_ASSESSED` for every binary although the
  tool already supported it. POSIX-only; honestly `BLOCKED` on other hosts, never silently `NOT_ASSESSED`.
- **Planner determinism contract pinned (`2a4235cb`).** The audit's "FIFO starvation" flag was verified
  *not* a defect (ties are a deterministic ordering rule; only recorded budget floors drop tasks), so the
  `next_task` ranking (priority → cost → FIFO), non-pending exclusion, and replan idempotency were locked
  with regression tests rather than by changing working, explainable code.
- **Reproducible assessment benchmark (`benchmark/`).** A new observer-only package runs the real pipeline
  against 13 controlled, local, authorized scenarios (web exposure, web-security config, REST + GraphQL
  input testing, network service identification, source secrets/deps/config/permissions, static binary
  analysis) with positive/negative/inconclusive/partial cases, and compares each `AssessmentState` +
  report against a declared expected outcome. It measures detection (produced *and* validated to the
  expected verdict), coverage-classification accuracy, a false-positive gate, report↔state consistency,
  and an `unexpected-confirmed` review list (0 for the current fixtures). Run with `python -m benchmark`;
  15 self-tests cover the framework. It establishes repeatable behaviour on controlled scenarios only and
  makes no real-world-target claim (§4).

---

## 3. Current working (what functions today)

**Agents (8):** `WebReconAgent`, `WebExposureAgent`, `WebSecurityAgent`, `NetworkReconAgent`,
`ServiceAssessmentAgent`, `SourceAssessmentAgent`, `InjectionTestAgent`, `BinaryAssessmentAgent`.

**Tools registered in the gateway (19):** `http_request`, `port_scan`, `banner_grab`,
`protocol_probe`, `secret_scan`, `dependency_audit`, `code_scan`, `config_scan`,
`permission_scan`, `repo_inventory`, `file_classify`, `file_inspect`, `sql_injection_probe`,
`xss_probe`, `ssrf_probe`, `binary_format_id`, `binary_hardening`, `binary_imports`, `binary_strings`.

**Supported target types that have working agents:**
- URL / web application (including GraphQL query-argument discovery and testing — see §2)
- Host / network service
- Local source directory
- Local binary executable (ELF / PE / Mach-O) — static analysis only, see §2

**Findings pipeline:**
`tool output → observation → candidate → validation → evidence → CONFIRMED | INCONCLUSIVE | REJECTED`.
HTTP 200 never confirms anything on its own — candidate paths are compared against a nonexistent-route
baseline (SPA catch-all detection) and must carry a content signature.

**Outputs:** Markdown + JSON reports to `raven_reports/raven_<id>.md` / `.json`; assessment state
persisted atomically to `~/.raven/assessments/<id>/` (supports pause / resume / crash recovery).

---

## 4. Accuracy & confidence

Raven's accuracy model is **evidence-based rather than optimistic**:

- **Independent validation is mandatory.** The agent that proposes a finding cannot confirm it; a
  separate validator re-observes the target and must see the behavior repeat. This is the direct fix
  for the previous engine's self-confirming findings.
- **False-positive controls:** SPA/route baselines and content signatures prevent catch-all `200`
  responses from being counted as real paths; XSS canaries that come back escaped are rejected;
  SQL probes are boolean/error-based with no writes.
- **Honest coverage:** anything not actually executed is reported as `NOT_ASSESSED` / `BLOCKED` /
  `NOT_APPLICABLE`, computed from what really ran — not assumed clean.
- **Test signal:** full repository suite confirmed at **241/241 passing**, no failures/skips. This round's
  GraphQL work adds 25 tests (11 pure-parser unit tests for `core/graphql_schema.py`, 4 probe-level unit
  tests for `location="graphql"` request building, 10 fixture-server integration tests through the full
  discover → test → validate pipeline); the same round's Binary Assessment Agent work adds another 25 (20
  unit tests against synthetic ELF/PE/Mach-O byte fixtures, 5 fixture-file integration tests through the
  full classify → assess → validate → report pipeline) — 191 (prior baseline) + 25 + 25 = 241, zero
  regressions to either the pre-existing suite or each other's work.

### Known accuracy boundaries (honest list)
- **Not implemented:** authorization/access-control testing, authenticated testing, and injection
  types beyond SQLi/XSS/SSRF (command injection, XXE, template injection) — all reported as `NOT_ASSESSED`.
- **Active injection** only exercises parameters Raven actually discovered — it is not a full crawl or
  fuzzer, and only runs at `--max-risk moderate`+. Discovery now covers forms, query strings, REST path
  segments, cookies, a published OpenAPI/Swagger spec, and GraphQL query arguments (via introspection), but
  still never blindly fuzzes headers or guesses JSON body fields it has no evidence for.
- **GraphQL** is now fed into active injection testing (SQLi + SSRF, query arguments only — see "What
  GraphQL Input Discovery v1 added" in §2 for the full scope and reasoning). Still not implemented: GraphQL
  mutation-argument testing (discovered but never actively tested — mutations write data) and GraphQL XSS
  (deferred: a JSON response's reflected payload is JSON-escaped, not HTML-escaped, and the existing
  tag-breakout heuristic would misclassify it as executable HTML/JS if applied unchanged).
- **SSRF confirmation** depends on the target reaching Raven's loopback callback, which usually is not
  possible across a real remote network boundary; a rejection there is reported as such, never as proof of absence.
- **Binary targets:** static-only analysis (format/arch ID, header-level hardening indicators, ELF import
  enumeration, embedded-string inspection — see "What Binary Assessment Agent v1 added" in §2). Not
  implemented: PE import-table parsing, Mach-O load-command parsing, and all dynamic/execution-based
  analysis (the binary is never run) — reported `PARTIALLY_ASSESSED`/`NOT_ASSESSED` accordingly, never as
  clean. **Classified but no agents yet:** containers, cloud, and Kubernetes targets.
- Knowledge retrieval is lexical (BM25), not embedding-based.
- File-permission auditing is POSIX-only (`BLOCKED` on Windows, verified live this round).
- Static-analysis hits are pattern-based; unsafe constructs stay `INCONCLUSIVE` until data flow is shown.
- Admin-panel/actuator/config-file exposure confirmation is now covered end-to-end by a fixture-server
  integration test (previously only unit-tested directly against the validator functions).

---

## 5. Summary

Raven is a **stable, tested v3.1** with a clean working tree. Beyond the original adaptive-engine rebuild
and the active-injection capability (SQLi/XSS/SSRF), recent rounds fixed a CLI crash on corrupt resume
state, silent partial-failure masking in `WebExposureAgent`, a budget-accounting bug that could silently
skip unrelated test coverage once a single narrow resource (expensive-op count) was used up, and closed
test-coverage gaps in content validation and permission scanning. This round added two new real
capabilities in parallel: schema-driven GraphQL input discovery (SQLi + SSRF, query arguments only — see
§2) after a prior round correctly deferred rather than rushed it, and a static-only Binary Assessment
Agent for ELF/PE/Mach-O targets (format/arch ID, hardening indicators, ELF imports, embedded-string
inspection — see §2) where previously no agent existed at all. Both new capabilities ride the existing
architecture unchanged: same Gateway/scope/budget/recovery path, same agent-raises-candidate/
validator-confirms discipline, same honest coverage vocabulary. Accuracy is enforced structurally —
separate validation, baseline comparison, and honest coverage reporting — and the test suite is fully
green (241/241). GraphQL mutation-argument testing, GraphQL XSS, PE import-table parsing, Mach-O
internals, and all dynamic/execution-based binary analysis remain explicit, documented gaps (not silently
missing). The clearest next priorities are those items plus authenticated/authorization testing.
