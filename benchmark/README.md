# Raven assessment benchmark

A small, reproducible benchmark that measures Raven's **actual assessment outcomes** on controlled,
local, authorized scenarios. It runs the real pipeline end to end and compares the resulting
`AssessmentState` + rendered report against a declared expected outcome. It is an *observer*: it never
fabricates a finding, relaxes a control, or changes the assessment architecture.

## Run

```bash
python -m benchmark                     # all scenarios + summary (exit non-zero on any failure)
python -m benchmark --list              # list scenarios
python -m benchmark --scenario ID ...   # run only the named scenario(s)
python -m benchmark --out PATH.json     # also write machine-readable results
```

State is written under an isolated temporary `RAVEN_HOME`, so a run never touches `~/.raven`.

## Layout

| File | Responsibility |
|---|---|
| `models.py` | `Scenario` / `ExpectedFinding` / `ScenarioResult`, scenario validation, and the deterministic `evaluate()` comparison. |
| `scenarios.py` | The scenario set and their fixtures (HTTP servers and ELF byte-builders reused from `tests/`; a threaded redis responder and temp-tree writers added here for standalone use). |
| `runner.py` | Executes scenarios through `core.assessment.run_assessment`, collects metrics, aggregates the summary. |
| `__main__.py` | CLI, isolation, human summary, JSON output, exit code. |

## Adding a scenario

Add a `Scenario(...)` to `SCENARIOS` in `scenarios.py` with a `setup` context manager that yields the
target string and cleans up, and expectations grounded in behaviour the integration suite already
trusts — never optimistic guesses. Ground every expected verdict; a benchmark that codifies wrong
expectations is worse than none. Run `python -m benchmark --scenario <id>` and confirm the
`unexpected-confirmed` list is empty (every real confirmation is accounted for) before committing.

## What it does not claim

It establishes repeatable behaviour on a defined set of controlled scenarios. It does **not** prove
Raven is effective against arbitrary real-world targets, and the set is too small for a
population-level false-positive or detection rate — the false-positive signal is the explicit
negative-case gate. See the "Assessment benchmark" section of the top-level `README.md` for the full
metric definitions and the not-yet-benchmarked list.
