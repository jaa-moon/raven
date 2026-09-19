"""
cli/menu.py
-----------
The main menu is intentionally simple:

    1. Test    2. Setup    3. Help    4. Version    5. Exit

All complexity (target analysis, planning, agents, validation, coverage) is
inside core.assessment.run_assessment; the menu never exposes it directly.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from config.manager import ConfigManager
from core.target import TargetError, parse_target
from reporting.generator import save, verdict
from ui.banner import print_banner
from ui.console import console

MENU = """[bold]1.[/] Test
[bold]2.[/] Setup
[bold]3.[/] Help
[bold]4.[/] Version
[bold]5.[/] Exit"""


def show_menu() -> None:
    print_banner(console)
    console.print(Panel(MENU, title="Raven — Autonomous Security Platform", border_style="magenta"))


async def run_test_flow(target_str: str | None = None, depth: str = "standard") -> None:
    console.print("\n[bold]RAVEN > TEST[/]\n")
    if not target_str:
        target_str = Prompt.ask("[cyan]Target[/]")
    try:
        parsed = parse_target(target_str)
    except TargetError as e:
        console.print(f"[red]{e}[/]")
        return

    if not Confirm.ask(f"Do you confirm you are authorized to assess [cyan]{parsed.normalized_target}[/]?", default=False):
        console.print("[red]Assessment aborted.[/]")
        return

    mgr = ConfigManager()
    cfg = mgr.load() if mgr.is_configured() else None

    from core.assessment import run_assessment

    def emit(kind: str, msg: str) -> None:
        console.print(f"[dim]{kind:12}[/] {msg}")

    with console.status(f"[bold green]Assessing {parsed.normalized_target}...[/]"):
        state = await run_assessment(target_str, depth=depth, llm_config=cfg, emit=emit, authorized=True)

    md_path, json_path = save(state, Path("raven_reports"))
    console.print(f"\n[bold]{state.overall_state}[/] — {verdict(state)}")
    console.print(f"Confirmed: {len(state.confirmed_findings)}  Inconclusive: {len(state.inconclusive_findings)}")
    console.print(f"Report: [cyan]{md_path}[/]")


def run_setup_flow() -> None:
    from ui.setup_wizard import run_setup_wizard
    run_setup_wizard(console, reconfigure=True)


def show_help() -> None:
    console.print(Panel(
        "Raven assesses an authorized target (URL, host, or local source tree).\n"
        "It classifies the target, plans capability-based tests, executes them through a scoped, "
        "budgeted tool gateway, independently validates every candidate finding, and reports honest "
        "coverage — findings are never inferred from an absence of evidence.\n\n"
        "Non-interactive: `python raven.py assess <target> --depth quick --fail-on high`.",
        title="Help", border_style="cyan"))


def show_version() -> None:
    console.print("[bold magenta]Raven[/] — Autonomous Security Assessment Platform, v3.1 (adaptive engine)")


async def interactive_menu() -> None:
    while True:
        show_menu()
        choice = Prompt.ask("\nSelect", choices=["1", "2", "3", "4", "5"], default="1")
        if choice == "1":
            await run_test_flow()
        elif choice == "2":
            run_setup_flow()
        elif choice == "3":
            show_help()
        elif choice == "4":
            show_version()
        else:
            console.print("Goodbye.")
            return
        console.print()


def main() -> None:
    asyncio.run(interactive_menu())


if __name__ == "__main__":
    main()
