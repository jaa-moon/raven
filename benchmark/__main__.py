"""
benchmark/__main__.py
---------------------
Command-line entry point for the Raven assessment benchmark.

    python -m benchmark                     # run all scenarios, print summary
    python -m benchmark --list              # list scenarios without running
    python -m benchmark --scenario ID ...   # run only the named scenario(s)
    python -m benchmark --out results.json  # also write machine-readable results

Exit code is 0 only when every scenario that ran passed; a failed or errored
scenario yields a nonzero exit (skipped scenarios do not fail the run). All
assessment state is written under an isolated temporary RAVEN_HOME so a
benchmark run never touches the operator's real ~/.raven.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List


def _meta() -> dict:
    import platform
    meta = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": platform.platform(), "python": platform.python_version(), "os_name": os.name}
    try:
        import subprocess
        meta["commit"] = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=Path(__file__).resolve().parent.parent,
            text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        meta["commit"] = "unknown"
    return meta


def _print_human(report: dict) -> None:
    s = report["summary"]
    print("\n=== Raven Assessment Benchmark ===")
    print(f"commit {report['meta'].get('commit')} | {report['meta'].get('platform')} | "
          f"python {report['meta'].get('python')}")
    print(f"\nScenarios: {s['scenarios_total']}  "
          f"passed={s['passed']}  failed={s['failed']}  skipped={s['skipped']}  error={s['error']}")

    def _acc(name, a):
        return f"{name}: {a['passed']}/{a['total']}" + ("" if a["total"] else " (n/a)")

    print("  " + "   ".join([
        _acc("detection", s["detection_accuracy"]),
        _acc("coverage", s["coverage_accuracy"]),
        _acc("false-positive gate", s["false_positive_gate"]),
        _acc("report", s["report_consistency"]),
    ]))
    print(f"  unexpected-confirmed (review): {s['unexpected_confirmed_total']}   "
          f"tool_calls={s['tool_calls_total']}   runtime={s['duration_s_total']}s")

    print("\nPer scenario:")
    for r in report["scenarios"]:
        mark = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP", "error": "ERR "}[r["status"]]
        m = r.get("metrics", {})
        extra = ""
        if r["status"] not in ("skipped", "error"):
            extra = (f"  [conf={m.get('findings_confirmed')} inc={m.get('findings_inconclusive')} "
                     f"rej={m.get('findings_rejected')} calls={m.get('tool_calls')} {m.get('duration_s')}s]")
        print(f"  {mark}  {r['id']:<34} ({r['kind']}/{r['target_type']}){extra}")
        if r["status"] == "skipped":
            print(f"         - {r['skip_reason']}")
        if r["status"] == "error":
            print(f"         ! {r['error'].splitlines()[-1] if r['error'] else 'error'}")
        for c in r.get("checks", []):
            if not c["passed"]:
                print(f"         x {c['name']}: {c['detail']}")
        for uc in m.get("unexpected_confirmed", []):
            print(f"         ? unexpected confirmed: [{uc['severity']}] {uc['title']} "
                  f"(validator={uc['validator']})")
    print()


async def _run(selected: List[str], out: Path | None) -> int:
    # Import after arg parsing so --list/--help stay fast and import errors surface clearly.
    from benchmark.models import validate_scenarios
    from benchmark.runner import build_report, exit_code, run_scenarios
    from benchmark.scenarios import SCENARIOS

    validate_scenarios(SCENARIOS)            # fail loudly on a malformed suite
    scenarios = SCENARIOS
    if selected:
        chosen = set(selected)
        scenarios = [s for s in SCENARIOS if s.id in chosen]
        missing = chosen - {s.id for s in scenarios}
        if missing:
            print(f"error: unknown scenario id(s): {', '.join(sorted(missing))}", file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory(prefix="raven_bench_home_") as home:
        os.environ["RAVEN_HOME"] = home                       # isolate state/lessons from the real ~/.raven
        state_root = Path(home) / "state"
        results = await run_scenarios(scenarios, state_root)

    report = build_report(results, meta=_meta())
    _print_human(report)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"wrote {out}")

    return exit_code(report["summary"])


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmark", description="Raven assessment benchmark")
    ap.add_argument("--scenario", action="append", default=[], metavar="ID",
                    help="run only this scenario id (repeatable); default runs all")
    ap.add_argument("--out", type=Path, default=None, metavar="PATH",
                    help="write machine-readable JSON results to this path")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = ap.parse_args()

    if args.list:
        from benchmark.scenarios import SCENARIOS
        for s in SCENARIOS:
            posix = "  (POSIX-only)" if s.posix_only else ""
            print(f"{s.id:<34} {s.kind:<10} {s.target_type:<18} {s.description}{posix}")
        return 0

    return asyncio.run(_run(args.scenario, args.out))


if __name__ == "__main__":
    sys.exit(main())
