"""
cli/app.py
----------
Main Typer CLI application for Raven.

`raven` with no subcommand shows the simple interactive menu (cli.menu).
`assess` / `scan` / `pentest` all run the adaptive engine (core.assessment);
`scan` and `pentest` are aliases so existing scripts and CI keep working.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import typer

if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") not in ("utf8", "utf16"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except AttributeError:
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from config.manager import ConfigManager
from core.state import StateLoadError
from core.target import TargetError
from ui.banner import print_banner
from ui.console import console
from ui.setup_wizard import run_setup_wizard

app = typer.Typer(name="raven", help="Raven — Autonomous Security Assessment Platform", no_args_is_help=False)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RISK_LEVELS = ("passive", "low", "moderate", "high")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        from cli.menu import main as menu_main
        menu_main()


def _run_adaptive(target: Optional[str], depth: str, fail_on: str, output: Optional[str], yes: bool = False,
                  resume: Optional[str] = None, max_risk: str = "low") -> None:
    from core.assessment import run_assessment
    from reporting.generator import save, verdict

    max_risk = (max_risk or "low").lower()
    if max_risk not in _RISK_LEVELS:
        console.print(f"[red]Invalid --max-risk '{max_risk}'. Choose one of: {', '.join(_RISK_LEVELS)}.[/]")
        raise typer.Exit(code=2)

    print_banner(console)
    console.print(f"  [bold cyan]Target:[/] {target}  |  [bold cyan]Depth:[/] {depth}  |  "
                  f"[bold cyan]Max risk:[/] {max_risk}\n")
    if max_risk != "low":
        console.print(f"  [yellow]Active testing enabled (max-risk={max_risk}): controlled SQL injection, "
                      "XSS and SSRF probes may run against discovered parameters.[/]\n")

    # --yes is the explicit non-interactive statement of authorization (e.g. for CI on your own repo).
    if not yes and not typer.confirm("Do you confirm you are authorized to assess this target?"):
        console.print("[red]Assessment aborted.[/]")
        raise typer.Exit(code=0)

    mgr = ConfigManager()
    cfg = mgr.load() if mgr.is_configured() else None

    def emit(kind: str, msg: str) -> None:
        console.print(f"[dim]{kind:12}[/] {msg}")

    try:
        with console.status(f"[bold green]Running Raven adaptive assessment on {target}...[/]"):
            state = asyncio.run(run_assessment(target, resume_id=resume, depth=depth, max_risk=max_risk,
                                               llm_config=cfg, emit=emit, authorized=True))
    except (StateLoadError, TargetError, PermissionError, ValueError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(code=1)

    md_path, json_path = save(state, Path(output) if output else Path("raven_reports"))
    console.print(f"\n[bold green]+ Assessment complete![/]  ID: [cyan]{state.assessment_id}[/]")
    console.print(f"  [bold]{state.overall_state}[/] — {verdict(state)}")
    console.print(f"  [bold]Findings:[/] {len(state.confirmed_findings)} confirmed, "
                  f"{len(state.inconclusive_findings)} inconclusive")
    console.print(f"  [bold]Report:[/] [cyan]{md_path}[/]\n")

    if fail_on != "none":
        threshold = _SEVERITY_RANK.get(fail_on.lower(), 99)
        for f in state.confirmed_findings:
            if _SEVERITY_RANK.get(f.severity.value, 99) <= threshold:
                console.print(f"[bold red]FAIL:[/] [{f.severity.value}] {f.title} meets --fail-on {fail_on}")
                raise typer.Exit(code=1)
        console.print(f"[bold green]PASS:[/] No findings at or above --fail-on {fail_on}.")


@app.command("assess")
def assess(
    target: Optional[str] = typer.Argument(None, help="Target: URL, host, IP, or local source directory."),
    depth: str = typer.Option("standard", "--depth", "-d", help="quick | standard | deep"),
    fail_on: str = typer.Option("none", "--fail-on", help="critical|high|medium|low|none"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Report output directory."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm authorization non-interactively."),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume a saved assessment by ID."),
    max_risk: str = typer.Option("low", "--max-risk", help="passive|low|moderate|high. moderate+ enables "
                                 "active SQL injection/XSS/SSRF probing."),
) -> None:
    """Run the adaptive assessment engine against any target type."""
    if not target and not resume:
        console.print("[red]Provide a target or --resume <assessment-id>.[/]")
        raise typer.Exit(code=2)
    _run_adaptive(target, depth, fail_on, output, yes, resume, max_risk)


@app.command("scan")
def scan(
    target_path: str = typer.Argument(..., help="Path to a local project/repository."),
    depth: str = typer.Option("standard", "--depth", "-d"),
    fail_on: str = typer.Option("none", "--fail-on"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm authorization non-interactively."),
    max_risk: str = typer.Option("low", "--max-risk", help="passive|low|moderate|high."),
) -> None:
    """Alias for `assess`, kept for existing scripts/CI (e.g. `raven scan . --yes`)."""
    _run_adaptive(target_path, depth, fail_on, output, yes, max_risk=max_risk)


@app.command("pentest")
def pentest(
    target_path: str = typer.Argument(...),
    depth: str = typer.Option("standard", "--depth", "-d"),
    fail_on: str = typer.Option("none", "--fail-on"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    max_risk: str = typer.Option("low", "--max-risk", help="passive|low|moderate|high."),
) -> None:
    """Alias for `assess`, kept for backward compatibility."""
    _run_adaptive(target_path, depth, fail_on, None, yes, max_risk=max_risk)


@app.command("setup")
def setup() -> None:
    """Run interactive setup wizard."""
    cfg = run_setup_wizard(console, reconfigure=True)
    if cfg:
        mgr = ConfigManager()
        mgr.save(cfg)
        console.print("[bold green]+ Configuration saved successfully![/]")


@app.command("report")
def report(assessment_id: str = typer.Argument(..., help="Assessment ID")) -> None:
    """Re-display a past assessment report."""
    matches = list(Path("raven_reports").glob(f"raven_{assessment_id}*.md")) or \
        list(Path(".").glob(f"**/raven_{assessment_id}*.md"))
    if not matches:
        console.print(f"[bold red]Report for assessment '{assessment_id}' not found.[/]")
        raise typer.Exit(code=1)
    console.print(matches[0].read_text(encoding="utf-8"))


@app.command("version")
def version() -> None:
    """Print Raven version info."""
    print_banner(console)
    console.print("  [bold magenta]Raven Autonomous Security Assessment Platform[/] v5.0.0 (Adaptive Agentic Engine)\n")
