# Raven — Project Status & Changes Report

**Date:** 2026-09-23
**Branch:** `master`
**Working tree:** clean
**Version line:** 3.1.0 (Adaptive engine rebuild)

---

## 1. Current stage

Raven is at the **v3.1 "adaptive assessment engine"** stage: a target-agnostic security
assessment platform that observes a target, works out what it is, plans capability-based tests,
runs them through a scoped and budgeted gateway, **independently validates** every candidate
finding, and reports honest coverage. It never treats "no findings" as "secure".

Core loop: `observe → understand → plan → act → observe → update context → re-plan`.

The codebase is ~10,950 lines of Python across clearly separated layers, with a **145-passing
test suite** (unit + integration against real local servers + regression). No failing or skipped
tests as of this run.

---

## 2. Recent changes

Most recent commits (newest first):

| Commit | Change |
|---|---|
| `6320c82` | **Active Injection Testing v1** — controlled SQLi / XSS / SSRF probing |
| `518c520` | **Rebuild** as a target-agnostic adaptive assessment engine (v3.1) |
| `4732e4f` | SPA-fallback detection and evidence-based path validation |
| `09a760c` | Checkpoint before the rebuild |

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
- Still not implemented: blind/arbitrary header fuzzing, JSON body fields with neither a spec nor a form to
  evidence them, and GraphQL variables (GraphQL still only gets a passive introspection check, never active
  injection testing) — Raven still never tests input surface it hasn't actually observed.

---

## 3. Current working (what functions today)

**Agents (7):** `WebReconAgent`, `WebExposureAgent`, `WebSecurityAgent`, `NetworkReconAgent`,
`ServiceAssessmentAgent`, `SourceAssessmentAgent`, `InjectionTestAgent`.

**Tools registered in the gateway (15):** `http_request`, `port_scan`, `banner_grab`,
`protocol_probe`, `secret_scan`, `dependency_audit`, `code_scan`, `config_scan`,
`permission_scan`, `repo_inventory`, `file_classify`, `file_inspect`, `sql_injection_probe`,
`xss_probe`, `ssrf_probe`.

**Supported target types that have working agents:**
- URL / web application
- Host / network service
- Local source directory

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
- **Test signal:** **145/145 tests pass** (unit + integration against real local servers + regression),
  giving confidence that the pipeline behaves as specified.

### Known accuracy boundaries (honest list)
- **Not implemented:** authorization/access-control testing, authenticated testing, and injection
  types beyond SQLi/XSS/SSRF (command injection, XXE, template injection) — all reported as `NOT_ASSESSED`.
- **Active injection** only exercises parameters Raven actually discovered — it is not a full crawl or
  fuzzer, and only runs at `--max-risk moderate`+. Discovery now covers forms, query strings, REST path
  segments, cookies, and a published OpenAPI/Swagger spec, but still never blindly fuzzes headers or guesses
  JSON body fields it has no evidence for.
- **SSRF confirmation** depends on the target reaching Raven's loopback callback, which usually is not
  possible across a real remote network boundary; a rejection there is reported as such, never as proof of absence.
- **Classified but no agents yet:** binaries, containers, cloud, and Kubernetes targets (reported as not assessed).
- Knowledge retrieval is lexical (BM25), not embedding-based.
- File-permission auditing is POSIX-only (`BLOCKED` on Windows).
- Static-analysis hits are pattern-based; unsafe constructs stay `INCONCLUSIVE` until data flow is shown.

---

## 5. Summary

Raven is a **stable, tested v3.1** with a clean working tree. The two most recent milestones were the
full adaptive-engine rebuild and the first controlled active-injection capability (SQLi/XSS/SSRF),
both gated behind scope, budget, and independent validation. Accuracy is enforced structurally —
separate validation, baseline comparison, and honest coverage reporting — and the 145-test suite is
fully green. The clearest next expansion areas are authenticated/authorization testing, additional
injection classes, and agents for the target types that are currently only classified.
