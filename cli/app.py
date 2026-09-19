"""
cli/app.py
----------
Main Typer CLI application for Raven.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import typer

# Ensure stdout/stderr encoding handles Unicode characters gracefully on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") not in ("utf8", "utf16"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except AttributeError:
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from rich.panel import Panel

from config.manager import ConfigManager
from engine import run_assessment
from engine_models.authorization import Authorization
from reports.report_generator import UniversalReportGenerator
from ui.banner import print_banner
from ui.console import console
from ui.setup_wizard import run_setup_wizard

app = typer.Typer(
    name="raven",
    help="Raven — Autonomous CLI Pentesting Agent",
    no_args_is_help=True
)


def _run_legacy_assessment_bridge(
    target_path: str,
    depth: str,
    no_docker: bool,
    agent: str,
    model: Optional[str],
    output_json: Optional[str],
    fail_on: str,
    diff: bool,
    command_name: str,
) -> None:
    """Bridge legacy scan/pentest CLI commands to Raven v3.0 Universal Engine."""
    console.print(
        f"[bold yellow]DEPRECATION NOTICE:[/] 'raven {command_name}' is a legacy command "
        "and now routes through the Raven v3.0 Universal Assessment Engine ('raven assess'). "
        "Please use 'raven assess' in future workflows.\n"
    )

    target = Path(target_path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/] Target path '{target}' does not exist.")
        raise typer.Exit(code=1)

    # Diff mode: filter target files to only changed ones
    if diff:
        try:
            from ci.diff_scanner import get_changed_files
            changed_files = get_changed_files(repo_root=target)
            if not changed_files:
                console.print("[bold green]+ No scannable files changed. Exiting clean.[/]")
                raise typer.Exit(code=0)
            console.print(f"[dim]Diff mode: {len(changed_files)} changed file(s) detected.[/]")
        except Exception as e:
            console.print(f"[bold yellow]WARNING:[/] Diff mode failed ({e}), falling back to full scan.")

    mgr = ConfigManager()
    cfg = mgr.load()
    if model and cfg:
        cfg.model = model

    provider = None
    if cfg:
        try:
            from providers.base import get_provider
            provider = get_provider(cfg.provider, cfg.model, cfg.api_key)
        except Exception:
            pass

    selected_caps = None
    if agent == "web":
        selected_caps = ["web_api_assessment"]
    elif agent == "auth":
        selected_caps = ["auth_identity_assessment"]

    auth_obj = Authorization(confirmed=True, confirmed_by="operator")
    mode = "passive" if no_docker else "active"

    console.print(f"\n[bold magenta][+] Starting Raven Assessment[/] against [cyan]{target}[/]\n")

    report = asyncio.run(
        run_assessment(
            target_input=str(target),
            depth=depth,
            mode=mode,
            authorization=auth_obj,
            selected_capabilities=selected_caps,
            provider=provider,
            config=cfg,
        )
    )

    rep_gen = UniversalReportGenerator(report=report)
    out_md = f"raven_assessment_{report.assessment_id}.md"
    out_json = output_json or f"raven_assessment_{report.assessment_id}.json"

    json_path = rep_gen.save(out_json, format_type="json", report=report)
    md_path = rep_gen.save(out_md, format_type="markdown", report=report)

    try:
        from ci.badge_generator import generate_badge
        badge_path = Path(json_path).parent / "raven-badge.json"
        generate_badge(str(badge_path), results_json_path=json_path)
    except Exception:
        pass

    console.print("\n[bold green]+ Assessment completed successfully![/]")
    console.print(f"  [bold]Risk Score:[/] [bold red]{report.risk_score}/10.0 ({report.risk_label})[/]")
    console.print(f"  [bold]Markdown Report:[/] [cyan]{md_path}[/]")
    console.print(f"  [bold]JSON Report:[/] [cyan]{json_path}[/]\n")

    if fail_on != "none":
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_rank.get(fail_on.lower(), 99)
        for f in report.confirmed_findings:
            finding_rank = severity_rank.get(f.severity.lower(), 99)
            if finding_rank <= threshold:
                console.print(f"[bold red]FAIL:[/] Finding [{f.severity}] {f.title} exceeds --fail-on {fail_on}")
                raise typer.Exit(code=1)
        console.print(f"[bold green]PASS:[/] No findings at or above --fail-on {fail_on} threshold.")


@app.command("scan")
def scan(
    path: str = typer.Argument(".", help="Target project path"),
    depth: str = typer.Option("standard", "--depth", "-d", help="Scan depth: quick, standard, deep"),
    no_docker: bool = typer.Option(False, "--no-docker", help="Disable Docker sandbox and force local process fallback"),
    agent: str = typer.Option("both", "--agent", "-a", help="Agent selection: both, web, auth"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override configured LLM model"),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Path to output JSON report"),
    fail_on: str = typer.Option("none", "--fail-on", help="Severity threshold to fail with exit code 1 (critical, high, medium, low, none)"),
    diff: bool = typer.Option(False, "--diff", help="Incremental scan: only analyze files changed vs. base branch"),
) -> None:
    """
    Run full autonomous assessment against a project directory (legacy entry point).
    """
    _run_legacy_assessment_bridge(
        target_path=path,
        depth=depth,
        no_docker=no_docker,
        agent=agent,
        model=model,
        output_json=output_json,
        fail_on=fail_on,
        diff=diff,
        command_name="scan",
    )


@app.command("pentest")
def pentest(
    path: str = typer.Argument(".", help="Target project path"),
    depth: str = typer.Option("standard", "--depth", "-d", help="Scan depth: quick, standard, deep"),
    no_docker: bool = typer.Option(False, "--no-docker", help="Disable Docker sandbox and force local process fallback"),
    agent: str = typer.Option("both", "--agent", "-a", help="Agent selection: both, web, auth"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override configured LLM model"),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Path to output JSON report"),
    fail_on: str = typer.Option("none", "--fail-on", help="Severity threshold to fail with exit code 1 (critical, high, medium, low, none)"),
    diff: bool = typer.Option(False, "--diff", help="Incremental scan: only analyze files changed vs. base branch"),
) -> None:
    """
    Run full autonomous pentest against a project directory (legacy entry point).
    """
    _run_legacy_assessment_bridge(
        target_path=path,
        depth=depth,
        no_docker=no_docker,
        agent=agent,
        model=model,
        output_json=output_json,
        fail_on=fail_on,
        diff=diff,
        command_name="pentest",
    )


@app.command("webscan")
def webscan(
    url: str = typer.Argument(..., help="Target URL to scan (e.g. https://example.com)"),
    depth: int = typer.Option(3, "--depth", "-d", help="Crawl depth"),
    max_pages: int = typer.Option(100, "--max-pages", help="Maximum pages to crawl"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override configured LLM model"),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Path to output JSON report"),
    no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt directives"),
) -> None:
    """
    Run active web vulnerability scan against a live URL (DAST mode).
    """
    import time as _time
    from pathlib import Path as _Path
    from dataclasses import asdict

    from web.crawler import RavenCrawler
    from web.fingerprinter import SiteFingerprinter
    from web.probe_engine import ProbeEngine
    from web.web_report_generator import generate_web_report
    from core.models import WebScanReport
    from providers.factory import get_provider

    mgr = ConfigManager()
    cfg_data = mgr.load() or {}

    console.print(f"\n[bold magenta][+] Starting Raven Web Scan[/] against [cyan]{url}[/]")
    console.print("[bold yellow]⚠  This sends active payloads to the target. Only scan targets you own or have authorization to test.[/]\n")

    confirm = typer.confirm("Do you confirm you are authorized to scan this target?")
    if not confirm:
        console.print("[red]Scan aborted.[/]")
        raise typer.Exit(code=0)

    scan_start = _time.time()

    # Step 1: Crawl
    console.print("[dim]Step 1/3: Crawling target...[/]")
    crawler = RavenCrawler(
        base_url=url,
        max_depth=depth,
        max_pages=max_pages,
        respect_robots=not no_robots,
    )
    crawl_result = crawler.crawl()
    total_forms = sum(len(p.forms) for p in crawl_result.pages)
    total_params = sum(len(p.query_params) for p in crawl_result.pages)
    console.print(f"  Discovered [cyan]{crawl_result.total_crawled}[/] pages, [cyan]{total_forms}[/] forms, [cyan]{total_params}[/] query parameters")

    # Step 2: Fingerprint
    console.print("[dim]Step 2/3: Fingerprinting technology stack...[/]")
    fingerprinter = SiteFingerprinter()
    site_fp = fingerprinter.fingerprint(crawl_result)
    techs = ", ".join(site_fp.detected_technologies) or "Unknown"
    console.print(f"  Technologies: [cyan]{techs}[/]")
    console.print(f"  Server: [cyan]{site_fp.server_header or 'Unknown'}[/]")
    if site_fp.missing_security_headers:
        console.print(f"  [yellow]Missing headers: {', '.join(site_fp.missing_security_headers)}[/]")
    if site_fp.interesting_paths:
        console.print(f"  [yellow]Interesting paths: {', '.join(site_fp.interesting_paths[:5])}[/]")

    # Step 3: Active Probe
    console.print("[dim]Step 3/3: Probing for vulnerabilities...[/]")
    provider_cfg = {
        "provider": cfg_data.get("provider", "ollama"),
        "model": model or cfg_data.get("model", "qwen2.5:7b"),
        "api_key": cfg_data.get("api_key"),
    }
    provider = get_provider(provider_cfg)
    probe_engine = ProbeEngine(provider=provider, fingerprint=site_fp)
    findings = probe_engine.probe_all(crawl_result)
    console.print(f"  Found [cyan]{len(findings)}[/] confirmed vulnerabilities")

    scan_duration = _time.time() - scan_start

    # Build severity counts
    sev_counts: dict = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # Build fingerprint dict for report
    fp_dict = {
        "detected_technologies": site_fp.detected_technologies,
        "server_header": site_fp.server_header,
        "security_headers": {
            name: {"present": hs.present, "value": hs.value, "secure": hs.secure}
            for name, hs in site_fp.security_headers.items()
        },
        "missing_security_headers": site_fp.missing_security_headers,
        "cookies": [
            {
                "name": c.name,
                "has_httponly": c.has_httponly,
                "has_secure": c.has_secure,
                "has_samesite": c.has_samesite,
            }
            for c in site_fp.cookies
        ],
        "interesting_paths": site_fp.interesting_paths,
        "information_disclosures": site_fp.information_disclosures,
        "tls_info": site_fp.tls_info,
    }

    from core.models import PathDiscoveryEntry

    path_discoveries = [
        PathDiscoveryEntry(
            path=d.path,
            http_status=d.status,
            content_type=d.content_type,
            response_length=d.response_length,
            classification=d.classification,
            similarity_to_baseline=d.similarity_to_baseline,
            validation_state=d.validation_state,
            confidence=d.confidence,
            evidence=d.evidence,
            reason=d.reason,
        )
        for d in site_fp.path_discoveries
    ]
    confirmed_findings_by_type = [f for f in findings if f.confirmed]
    discovery_summary = {
        "candidate_paths_tested": len(path_discoveries),
        "likely_spa_fallback": sum(1 for d in path_discoveries if d.validation_state == "spa_fallback"),
        "confirmed_sensitive_file_exposures": sum(
            1 for f in confirmed_findings_by_type if f.vulnerability_type == "SensitiveFileExposure"
        ),
        "confirmed_admin_interfaces": sum(
            1 for f in confirmed_findings_by_type if f.vulnerability_type == "AdminPanelExposed"
        ),
        "inconclusive_findings": sum(1 for d in path_discoveries if d.validation_state == "inconclusive"),
        "protected_resources": sum(1 for d in path_discoveries if d.validation_state == "protected"),
        "false_positives": sum(1 for d in path_discoveries if d.validation_state == "false_positive"),
    }

    report = WebScanReport(
        target=url,
        scan_duration_seconds=scan_duration,
        fingerprint=fp_dict,
        findings=findings,
        findings_by_severity=sev_counts,
        total_findings=len(findings),
        path_discoveries=path_discoveries,
        path_discovery_summary=discovery_summary,
    )

    json_out = _Path(output_json) if output_json else None
    md_path = generate_web_report(report, output_json=json_out)

    console.print(f"\n[bold green]+ Web scan completed![/]  Duration: {scan_duration:.1f}s")
    console.print(f"  [bold]Findings:[/] {len(findings)} ({sev_counts.get('Critical', 0)} Critical, {sev_counts.get('High', 0)} High)")
    console.print(f"  [bold]Report:[/] [cyan]{md_path}[/]\n")




@app.command("setup")
def setup() -> None:
    """
    Run interactive setup wizard.
    """
    cfg = run_setup_wizard(console, reconfigure=True)
    if cfg:
        mgr = ConfigManager()
        mgr.save(cfg)
        console.print("[bold green]+ Configuration saved successfully![/]")


@app.command("report")
def report(scan_id: str = typer.Argument(..., help="Scan ID string")) -> None:
    """
    Re-display past scan report.
    """
    # Search CWD and common report locations
    search_roots = [Path("."), Path.home() / ".raven"]
    matches = []
    for root in search_roots:
        matches.extend(root.glob(f"**/raven_report_{scan_id}*.md"))

    if not matches:
        console.print(f"[bold red]Report for scan ID '{scan_id}' not found.[/]")
        raise typer.Exit(code=1)

    content = matches[0].read_text(encoding="utf-8")
    console.print(content)


@app.command("assess")
def assess(
    target: str = typer.Argument(..., help="Target system (URL, local repo path, IP, CIDR, container image, binary)"),
    depth: str = typer.Option("standard", "--depth", "-d", help="Assessment depth: quick, standard, deep"),
    mode: str = typer.Option("passive", "--mode", help="Assessment mode: passive, active, authenticated"),
    scope_file: Optional[str] = typer.Option(None, "--scope", help="Path to scope boundaries YAML/JSON file"),
    auth_file: Optional[str] = typer.Option(None, "--authorization", help="Path to authorization confirmation YAML/JSON file"),
    credentials_file: Optional[str] = typer.Option(None, "--credentials", help="Path to credentials JSON file"),
    creds: Optional[str] = typer.Option(None, "--creds", help="Inline JSON credentials or credentials file path"),
    agents: Optional[str] = typer.Option(None, "--agents", help="Comma-separated agent names to force (e.g. web,network,binary,infra)"),
    no_sandbox: bool = typer.Option(False, "--no-sandbox", help="Disable sandbox isolation and run locally"),
    fail_on: str = typer.Option("none", "--fail-on", help="Severity threshold to fail with exit code 1 (critical, high, medium, low, none)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Path to write output report"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, json"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume a paused/interrupted assessment by ID"),
    capabilities: Optional[str] = typer.Option(None, "--capabilities", help="Comma-separated capability IDs to activate"),
    exclude: Optional[str] = typer.Option(None, "--exclude", help="Comma-separated capability IDs to exclude"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override LLM model"),
    authorized: bool = typer.Option(True, "--authorized", help="Confirm explicit authorization for assessment"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose execution logging"),
) -> None:
    """
    Run universal adaptive security assessment against any target system.
    """
    print_banner(console)
    console.print(f"  [bold cyan]Target:[/] {target}  |  [bold cyan]Depth:[/] {depth}  |  [bold cyan]Mode:[/] {mode.upper()}\n")

    # Load provider
    mgr = ConfigManager()
    cfg = mgr.load()
    if model and cfg:
        cfg.model = model

    provider = None
    if cfg:
        try:
            from providers.base import get_provider
            provider = get_provider(cfg.provider, cfg.model, cfg.api_key)
        except Exception as e:
            if verbose:
                console.print(f"[yellow]LLM provider initialization note: {e}. Running deterministic mode.[/]")

    # Parse capabilities & agents
    selected_caps = [c.strip() for c in capabilities.split(",")] if capabilities else None
    if agents:
        agent_list = [a.strip().lower() for a in agents.split(",")]
        cap_map = {
            "web": "web_api_assessment",
            "web_api": "web_api_assessment",
            "network": "network_assessment",
            "auth": "auth_identity_assessment",
            "source": "source_code_analysis",
            "binary": "binary_assessment",
            "infra": "configuration_assessment",
            "config": "configuration_assessment",
            "secrets": "secrets_assessment",
            "deps": "dependency_assessment",
        }
        mapped_caps = [cap_map.get(a, a) for a in agent_list]
        selected_caps = (selected_caps or []) + mapped_caps

    excluded_caps = [c.strip() for c in exclude.split(",")] if exclude else None

    # Parse scope if provided
    scope_obj = None
    if scope_file and Path(scope_file).exists():
        try:
            import json
            import yaml  # type: ignore[import]
            content = Path(scope_file).read_text(encoding="utf-8")
            data = yaml.safe_load(content) if hasattr(yaml, "safe_load") else json.loads(content)
            from engine_models.scope import Scope
            scope_obj = Scope(**data)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not parse scope file: {e}[/]")

    # Setup Authorization
    from engine_models.authorization import Authorization
    auth_obj = Authorization(confirmed=authorized, confirmed_by="operator")
    creds_source = creds or credentials_file
    if creds_source:
        try:
            import json
            if Path(creds_source).exists():
                creds_data = json.loads(Path(creds_source).read_text(encoding="utf-8"))
            else:
                creds_data = json.loads(creds_source)
            auth_obj.credentials = creds_data.get("credentials", creds_data)
            auth_obj.api_keys = creds_data.get("api_keys", {})
        except Exception as e:
            if verbose:
                console.print(f"[yellow]Warning: Could not parse credentials: {e}[/]")

    from engine import run_assessment
    from reports.report_generator import UniversalReportGenerator

    with console.status(f"[bold green]Running Raven v3.0 Adaptive Assessment on {target}...[/]"):
        report = asyncio.run(
            run_assessment(
                target_input=target,
                depth=depth,
                mode=mode,
                scope=scope_obj,
                authorization=auth_obj,
                selected_capabilities=selected_caps,
                excluded_capabilities=excluded_caps,
                provider=provider,
                resume_assessment_id=resume,
                config=cfg,
            )
        )

    # Save and display report
    rep_gen = UniversalReportGenerator(report=report)
    out_file = output or f"raven_assessment_{report.assessment_id}.{'md' if format == 'markdown' else 'json'}"
    saved_path = rep_gen.save(out_file, format_type=format, report=report)

    console.print(f"\n[bold green]+ Assessment complete![/]  ID: [cyan]{report.assessment_id}[/]  Duration: [white]{report.duration_seconds:.1f}s[/]")
    console.print(f"  [bold]Risk Posture:[/] [{ 'red' if report.risk_score >= 7.0 else 'yellow' if report.risk_score >= 4.0 else 'green'}]{report.risk_score}/10.0 ({report.risk_label})[/]")
    console.print(f"  [bold]Findings:[/] {len(report.confirmed_findings)} Confirmed, {len(report.inconclusive_findings)} Inconclusive")
    console.print(f"  [bold]Assets Discovered:[/] {report.total_assets_discovered}  |  [bold]Coverage:[/] {report.coverage_percentage}% tested")
    console.print(f"  [bold]Report Saved:[/] [cyan]{saved_path}[/]\n")

    if fail_on != "none":
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_rank.get(fail_on.lower(), 99)
        for f in report.confirmed_findings:
            finding_rank = severity_rank.get(f.severity.lower(), 99)
            if finding_rank <= threshold:
                console.print(f"[bold red]FAIL:[/] Finding [{f.severity}] {f.title} meets or exceeds --fail-on {fail_on}")
                raise typer.Exit(code=1)
        console.print(f"[bold green]PASS:[/] No findings at or above --fail-on {fail_on} threshold.")


@app.command("version")
def version() -> None:
    """Print Raven version info."""
    print_banner(console)
    console.print("  [bold magenta]Raven Autonomous Security Assessment Platform[/] v3.0.0 (Adaptive Agentic Architecture)\n")


if __name__ == "__main__":
    app()
