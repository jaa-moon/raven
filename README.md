# Raven — Autonomous Security Assessment Platform

Raven assesses an **authorized** target (URL, host/IP, or local source tree). It works out what the
target is, plans capability-based tests, executes them through a scoped and budgeted tool gateway,
**independently validates** every candidate finding, and reports honest coverage. It never treats
"no findings" as "secure".

```
observe → understand → plan → act → observe → update context → re-plan
```

## Quick start

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

## Current limitations (honest list)

- **Not implemented:** authorization/access-control testing, authenticated testing, and injection types
  beyond SQLi/XSS/SSRF (e.g. command injection, XXE, template injection). These appear in every web report
  as `NOT_ASSESSED`.
- **Active injection testing** (SQLi/XSS/SSRF) only exercises parameters Raven actually discovered (forms,
  query strings, the REST `id` convention) — it is not a full crawl or fuzzer, and only runs when scope is
  raised to `--max-risk moderate` or higher. SSRF confirmation depends on the target being able to reach
  Raven's loopback callback, which is not true across most real network boundaries for a remote target;
  a rejection there is reported as such, never as proof of absence.
- **Target types:** URL/web, host/network service, and source directory are supported. Binaries, containers,
  cloud and Kubernetes targets are classified but have no agents yet (coverage reports them as not assessed).
- Knowledge retrieval is lexical (BM25), not embedding-based.
- File-permission auditing is POSIX-only (reported as `BLOCKED` on Windows).
- Static-analysis hits are pattern-based; unsafe constructs stay `INCONCLUSIVE` until data flow is shown.

## Security

See `SECURITY.md`. Only assess systems you own or are explicitly authorized to test.
