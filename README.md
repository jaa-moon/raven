# Raven — Autonomous Security Assessment Platform

Raven assesses an **authorized** target (URL, host/IP, or local source tree). It works out what the
target is, plans capability-based tests, executes them through a scoped and budgeted tool gateway,
**independently validates** every candidate finding, and reports honest coverage. It never treats
"no findings" as "secure".

```
observe → understand → plan → act → observe → update context → re-plan
```

## Quick start

**Requirements:** Python 3.11+ (developed and tested on 3.11; POSIX or Windows). No external services are
required — an LLM is optional (see below), and file-permission auditing is POSIX-only.

```bash
python -m venv venv && venv/Scripts/activate      # or: source venv/bin/activate
pip install -r requirements.txt

python raven.py                                   # simple menu: Test / Setup / Help / Version / Exit
python raven.py assess http://localhost:3000 --depth quick
python raven.py assess http://localhost:3000 --max-risk moderate   # enables active SQLi/XSS/SSRF probing
python raven.py assess ./my-project --fail-on high --yes    # --yes = "I am authorized" (CI)
python raven.py setup                             # optional: configure a local or API LLM
```

An LLM is **optional**. Without one Raven runs fully rule-based; with one it helps interpret the target
and prioritize tasks (it can never override scope, budget, tool schemas or validation).

Reports are written to `raven_reports/raven_<id>.md` and `.json`; state to `~/.raven/assessments/<id>/`
(`RAVEN_HOME` overrides).

## Architecture

| Layer | Package | Responsibility |
|---|---|---|
| Intake | `core/target.py` | Parse/normalize input; never tests anything |
| Analysis | `intelligence/target_analyzer.py` | "What am I looking at?" → `TargetProfile` |
| Knowledge (RAG) | `intelligence/rag.py`, `context.py`, `lessons.py`, `knowledge/` | Checklists, cases, validated lessons; retrieved by *current context* |
| Planner | `intelligence/planner.py` | Chooses next work from profile + tools + budget + history; re-plans every iteration |
| Agents | `agents/` | Propose tasks, request **capabilities** (never tools) |
| MCP gateway | `raven_mcp/` | Capability→tool resolution, arg validation, **scope**, **budget**, timeout, normalization, logging |
| Tools | `tools/` | Concrete scanners registered with capability metadata in `tools/catalog.py` |
| Validation | `validation/` | Re-observes the target; SPA/response baselines; content signatures; redaction |
| Recovery | `recovery/` | Classifies failures → retry / backoff / alternative tool / correct args / skip / block (all recorded) |
| State | `core/state.py` | The single source of truth; atomic persistence |
| Coverage | `core/coverage.py` | Computed from what actually ran |
| Report | `reporting/` | One honest report pipeline |
| Runtime | `core/assessment.py`, `core/runtime.py` | The adaptive loop (small, testable stages) |

Separation of duties: RAG = knowledge · LLM = reasoning · Planner = decisions · Agents = specialized
behavior · Gateway = controlled tool access · Scope/Budget = boundaries · Validator = evidence ·
State = truth · Report = output.

### Findings pipeline

`tool output → observation → candidate finding → validation → evidence → CONFIRMED | INCONCLUSIVE | REJECTED`.
Agents can only create candidates. HTTP 200 never confirms anything: candidate paths are compared with a
nonexistent-route baseline (SPA catch-all detection) and must carry a content signature.

### Interpreting a report

A finding is **CONFIRMED** only after an independent re-check reproduced the behaviour with evidence;
**INCONCLUSIVE** means a signal was seen but exploitability was not proven (e.g. a pattern match without
data-flow) — investigate, don't dismiss; **REJECTED** candidates are filtered false positives, reported as
a count so you can see they were considered. Per-surface **coverage** is separate from findings:
`ASSESSED` (a test ran to completion), `PARTIALLY_ASSESSED` (ran with gaps), `NOT_ASSESSED` (no test ran —
never treat as "clean"), `BLOCKED` (applicable but the platform/tool made it impossible, e.g. POSIX-only
permission auditing on Windows), `NOT_APPLICABLE` (the surface doesn't exist for this target type). "No
confirmed findings" is always qualified by how much was actually assessed — Raven never reports "clean".

### Active injection testing (SQLi / XSS / SSRF)

`InjectionTestAgent` (`agents/injection.py`) discovers real input surface (forms, query-string parameters,
the REST `id` convention) and requests `injection.sql.detect` / `injection.xss.reflect` / `injection.ssrf.detect`
through the gateway — the same scope/budget/recovery path as every other capability. It only raises
candidates; `validation/checks_injection.py` independently re-probes (via `injection.*.validate`) and requires
the behavior to repeat before confirming anything. Payloads are non-destructive: boolean/error-based SQL
probes (no writes), one reflected canary marker for XSS (context-classified, escaped reflection rejected),
and SSRF detection via a Raven-hosted loopback callback canary rather than an arbitrary external host.
**Active probing only runs above the default scope risk ceiling** (`assess --max-risk moderate`); below that
it is recorded as an explicit limitation, never silently skipped, and no active request is ever attempted.

Since introspection is enabled, this also covers **GraphQL query arguments** (`agents/web_recon.py` parses
a full introspection response via `core/graphql_schema.py` into testable scalar leaf arguments — top-level or
nested inside an input object — while skipping any field with a required list/enum/unresolvable-type argument
rather than guessing). GraphQL SQLi/SSRF ride the same discovery → candidate → independent-revalidation
pipeline as REST. **Not covered:** GraphQL mutation arguments (mutations write data; safely defaulting an
arbitrary mutation's full argument set without a live target to validate against was judged too large to
implement with confidence in one pass) and GraphQL XSS (a GraphQL response is JSON-escaped, not
HTML-escaped, and the shared REST/HTML reflection heuristic would misclassify inert JSON-context reflection
as executable — rather than weaken that shared heuristic, GraphQL XSS testing was left out entirely). Both
are documented gaps, not silent omissions.

### Binary analysis (static only)

`BinaryAssessmentAgent` (`agents/binary.py`) assesses a single authorized local ELF/PE/Mach-O executable:
format and architecture identification, header-level hardening indicators (ELF NX-stack/RELRO-proxy/
PIE-proxy; PE ASLR/DEP), ELF `DT_NEEDED` imported-library enumeration, embedded-string inspection
(secret-shaped and internal-host-shaped strings are flagged and redacted before they reach a report, the
same way `tools/secret_scanner.py` redacts source-code secrets), and an audit of the binary file's **own
filesystem permissions** (SUID/SGID, world-writable — a direct local-privilege-escalation surface, POSIX-only
and reported as `BLOCKED` elsewhere). All parsing is hand-rolled with `struct` —
no new dependency. **The target binary is never executed, mapped, or sandboxed** — this is a static-only
first milestone. Not implemented: PE import-table parsing, Mach-O load-command parsing (hardening/imports
stay unsupported for Mach-O), and all dynamic/execution-based analysis (the `Process & CLI` coverage surface
stays `NOT_ASSESSED`, never rendered as clean).

### Adding a capability

1. Add a tool: `ToolDefinition(name=…, capabilities=[…], input_schema=…, risk_level=…, scope_args=…, handler=…)`
   in `tools/catalog.py`.
2. Add an agent (`agents/base.py::Agent`): `applies()`, `propose_tasks()`, `run()`; register it in
   `agents/registry.py`.
3. Add a validator (`_v_<signal>` in `validation/`) for any finding type it emits.

No core changes are required.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest            # unit + integration (real local servers) + regression
```

## Assessment benchmark

`benchmark/` measures Raven's **actual assessment outcomes** on a fixed set of controlled, local,
authorized scenarios — not whether individual functions return expected values (the test suite does
that). Each scenario runs the real pipeline (intake → analysis → planner → gateway → agents →
independent validation → coverage → report) against a synthetic fixture and compares the resulting
`AssessmentState` and rendered report to a declared expected outcome.

```bash
python -m benchmark                    # run all scenarios, print a summary
python -m benchmark --list             # list scenarios without running
python -m benchmark --scenario source-vulns --scenario network-redis   # run a subset
python -m benchmark --out benchmark/results/latest.json                # also write JSON
```

The suite spans web exposure, web-security configuration, REST and GraphQL input testing, network
service identification, source secrets/dependencies/config/permissions, and static binary analysis,
with **positive** cases (a known condition must be confirmed), **negative** cases (nothing may be
confirmed — the false-positive gate), an **inconclusive** case (a pattern is seen but exploitability
is unproven), and **partial/gated** cases (e.g. active injection correctly disabled at low risk). It
exits non-zero if any scenario that ran fails.

Each scenario records, and the summary aggregates:

- **detection** — expected findings that were produced *and* independently validated to the expected
  verdict (a missing finding is distinguished from a wrong verdict);
- **coverage** — per-surface coverage classified honestly (an over-claim such as `NOT_ASSESSED`
  reported as `ASSESSED`, or the reverse, fails);
- **false-positive gate** — forbidden findings that were (correctly) never confirmed in negative cases;
- **report consistency** — every confirmed finding appears in the report, and the report's headline
  counts and coverage table match the persisted state;
- **unexpected-confirmed** — confirmed findings a scenario did not enumerate, surfaced for review
  (for the current fixtures this is 0; a non-zero value flags a new true finding *or* a regression);
- tool-call count and wall-clock duration per scenario.

**What it does not measure / not yet benchmarked:** it makes no claim about real-world targets — it
establishes *repeatable behaviour on a defined set of controlled scenarios only*. The current set is
small, so it does not support a statistically meaningful population false-positive or detection rate;
the false-positive signal is the explicit negative-case gate, not a rate. Not yet benchmarked:
authenticated/authorization testing (unimplemented), injection types beyond SQLi/XSS/SSRF, GraphQL
mutation testing (a documented gap), Mach-O/PE import hardening facets, container/cloud/Kubernetes
targets, and — on a non-POSIX host — the SUID file-permission scenario (skipped, not failed).

## Current limitations (honest list)

- **Not implemented:** authorization/access-control testing, authenticated testing, and injection types
  beyond SQLi/XSS/SSRF (e.g. command injection, XXE, template injection). These appear in every web report
  as `NOT_ASSESSED`.
- **Active injection testing** (SQLi/XSS/SSRF) only exercises parameters Raven actually discovered (forms,
  query strings, the REST `id` convention) — it is not a full crawl or fuzzer, and only runs when scope is
  raised to `--max-risk moderate` or higher. SSRF confirmation depends on the target being able to reach
  Raven's loopback callback, which is not true across most real network boundaries for a remote target;
  a rejection there is reported as such, never as proof of absence.
- **GraphQL:** query-argument discovery and active SQLi/SSRF testing only. Mutation arguments are discovered
  but never actively tested (data-writing, no live target to validate a safe baseline against); GraphQL XSS
  is not tested at all (see above).
- **Target types:** URL/web, host/network service, and source directory are fully supported. Local binaries
  (ELF/PE/Mach-O) get static-only analysis — see above; dynamic/execution-based binary analysis is not
  implemented. Containers, cloud, and Kubernetes targets are classified but have no agents yet.
- Knowledge retrieval is lexical (BM25), not embedding-based.
- File-permission auditing is POSIX-only (reported as `BLOCKED` on Windows).
- Static-analysis hits are pattern-based; unsafe constructs stay `INCONCLUSIVE` until data flow is shown.

## Security

See `SECURITY.md`. Only assess systems you own or are explicitly authorized to test.
