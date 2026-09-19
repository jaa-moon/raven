"""
ui/dashboard.py
----------------
Live dual-agent split panel dashboard using Rich Live.
"""

from __future__ import annotations

import time
from typing import Any, Optional
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from orchestrator.findings_bus import FindingsBus
from reports.models import AgentFinding, ProjectProfile


class LiveDashboard:
    """
    Renders real-time progress for Agent 1, Agent 2, Findings Bus,
    and (optionally) live MCP tool call log.
    """

    def __init__(
        self,
        console: Console,
        profile: ProjectProfile,
        bus: FindingsBus,
        gateway: Optional[Any] = None,
    ) -> None:
        self.console = console
        self.profile = profile
        self.bus = bus
        self.gateway = gateway
        self.start_time = time.time()

    def make_layout(self, agent1_status: str = "Active", agent2_status: str = "Active") -> Layout:
        layout = Layout()

        has_gateway = self.gateway is not None

        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=12 if has_gateway else 8)
        )
        layout["main"].split_row(
            Layout(name="agent1"),
            Layout(name="agent2")
        )

        elapsed = int(time.time() - self.start_time)
        layout["header"].update(
            Panel(f"[bold magenta]🐦 RAVEN Autonomous Pentest[/] • Target: [cyan]{self.profile.path}[/] • Elapsed: [yellow]{elapsed}s[/]", border_style="magenta")
        )

        # Agent 1 Panel
        a1_table = Table.grid(padding=(0, 1))
        a1_table.add_row("Status:", f"[green]{agent1_status}[/]")
        a1_table.add_row("Findings:", f"[bold red]{len(self.bus.findings_by_agent('web_api'))}[/]")
        layout["agent1"].update(Panel(a1_table, title="[bold cyan]AGENT 1 — Web/API Surface[/]", border_style="cyan"))

        # Agent 2 Panel
        a2_table = Table.grid(padding=(0, 1))
        a2_table.add_row("Status:", f"[green]{agent2_status}[/]")
        a2_table.add_row("Findings:", f"[bold red]{len(self.bus.findings_by_agent('auth_infra'))}[/]")
        layout["agent2"].update(Panel(a2_table, title="[bold blue]AGENT 2 — Auth & Infra[/]", border_style="blue"))

        # Footer — Findings Bus + Tool Call Log
        if has_gateway:
            footer_layout = Layout()
            footer_layout.split(
                Layout(name="findings_panel", ratio=1),
                Layout(name="tools_panel", ratio=1),
            )

            # Findings Bus
            findings = self.bus.all_findings()
            bus_text = "\n".join([f"[{f.severity}] {f.agent.upper()}: {f.vulnerability_type} @ {f.target_url}" for f in findings[-4:]])
            footer_layout["findings_panel"].update(
                Panel(bus_text or "[dim]Waiting for findings...[/]", title="[bold red]SHARED FINDINGS BUS[/]", border_style="red")
            )

            # Tool Call Log
            recent_calls = self.gateway.last_calls(n=4)
            if recent_calls:
                tool_lines = []
                for entry in recent_calls:
                    status_icon = "[green]✓[/]" if entry.result.success else "[red]✗[/]"
                    duration = f"{entry.result.duration_ms:.0f}ms"
                    params_summary = ", ".join(f"{k}={v}" for k, v in list(entry.params.items())[:2])
                    tool_lines.append(f"{status_icon} [cyan]{entry.tool_name}[/]({params_summary}) [{duration}]")
                tools_text = "\n".join(tool_lines)
            else:
                tools_text = "[dim]No tool calls yet...[/]"

            total = self.gateway.total_calls()
            footer_layout["tools_panel"].update(
                Panel(tools_text, title=f"[bold yellow]MCP TOOL CALLS[/] ({total} total)", border_style="yellow")
            )

            layout["footer"].update(footer_layout)
        else:
            # No gateway — just show findings bus
            findings = self.bus.all_findings()
            bus_text = "\n".join([f"[{f.severity}] {f.agent.upper()}: {f.vulnerability_type} @ {f.target_url}" for f in findings[-5:]])
            layout["footer"].update(Panel(bus_text or "[dim]Waiting for findings...[/]", title="[bold red]SHARED FINDINGS BUS[/]", border_style="red"))

        return layout
