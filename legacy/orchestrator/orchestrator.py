"""
orchestrator/orchestrator.py
-----------------------------
Master scan orchestrator with LLM pre-flight validation, real-time console
output, LLM-generated executive summaries, and intelligent chain synthesis.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from pathlib import Path
from agents.auth_infra_agent import AuthInfraAgent
from agents.web_api_agent import WebApiAgent
from core.ast_compressor import ASTCompressor
from core.file_analyzer import FileAnalyzer
from orchestrator.findings_bus import FindingsBus
from orchestrator.project_classifier import ProjectClassifier
from orchestrator.tool_selector import ToolSelector
from providers.base import BaseProvider
from providers.factory import get_provider
from rag.feedback_loop import FeedbackLoop
from rag.retriever import SecurityRetriever
from reports.models import AttackChain, FinalReport, RavenConfig
from reports.risk_classifier import RiskClassifier
from sandbox.sandbox_manager import SandboxManager
from ui.console import console


async def run_scan(target_path: Path | str, config: RavenConfig) -> FinalReport:
    """
    Execute autonomous pentest against target path.
    """
    start_time = time.time()
    scan_start_iso = datetime.now().isoformat()
    path = Path(target_path).resolve()

    # Step 1 — Project Classification
    console.print("[dim]Step 1/8: Classifying target project...[/]")
    classifier = ProjectClassifier(path)
    profile = classifier.classify()
    console.print(f"  Stack: [bold cyan]{profile.language}[/] + [bold cyan]{profile.framework}[/]")
    console.print(f"  Entry: [cyan]{profile.entry_point}[/] | Port: [cyan]{profile.detected_port}[/]")
    console.print(f"  Routes: [cyan]{', '.join(profile.detected_routes[:5])}[/]")
    console.print(f"  Dependencies: [cyan]{len(profile.dependencies)}[/] packages")

    # Step 2 — Provider Pre-flight
    console.print("\n[dim]Step 2/8: Validating LLM provider...[/]")
    provider_config = {"provider": config.provider, "model": config.model, "api_key": config.api_key}
    provider = get_provider(provider_config)

    llm_ok = _preflight_llm(provider)
    if llm_ok:
        console.print(f"  [bold green]OK[/] — {provider.provider_name} / {provider.model_name} responding")
    else:
        console.print(f"  [bold yellow]WARNING[/] — {provider.provider_name} / {provider.model_name} NOT responding")
        console.print("  [yellow]Scan will continue but AI analysis will use fallback heuristics.[/]")
        console.print("  [yellow]Check: Is Ollama running? Is the model pulled? Try: ollama list[/]")

    # Step 3 — RAG Tool & Technique Selection + Feedback Loop
    console.print("\n[dim]Step 3/8: Loading RAG knowledge base...[/]")
    retriever = SecurityRetriever()

    # Load historical attack patterns from feedback loop
    feedback = FeedbackLoop()
    prioritized_techniques = []
    try:
        prioritized_techniques = feedback.get_prioritized_techniques(profile)
        if prioritized_techniques:
            console.print(f"  Memory: [cyan]{len(prioritized_techniques)}[/] prioritized techniques from past scans")
    except Exception:
        pass

    selector = ToolSelector(retriever, profile, depth=config.depth)
    tool_plan = selector.select()
    console.print(f"  Agent 1 tools: [cyan]{', '.join(tool_plan['web_api'])}[/]")
    console.print(f"  Agent 2 tools: [cyan]{', '.join(tool_plan['auth_infra'])}[/]")
    rag_chunks = tool_plan.get("rag_context", [])
    console.print(f"  RAG context: [cyan]{len(rag_chunks)}[/] knowledge chunks loaded")

    # Step 3.5 — AST Context Compression
    console.print("\n[dim]Step 3.5/8: Running AST Context Compression...[/]")
    compressor = ASTCompressor()
    file_analyzer = FileAnalyzer(provider, compressor, rag_chunks)
    source_results = file_analyzer.analyze_project(path, profile.language)
    source_snippets: list[str] = []
    if source_results:
        summary = file_analyzer.compression_summary()
        console.print(
            f"  AST Compression: [cyan]{summary.get('files_compressed', 0)}[/] files compressed "
            f"({summary.get('overall_ratio', 1.0)}x ratio, [bold green]{summary.get('estimated_token_reduction_pct', 0)}% token reduction[/])"
        )
        for res in source_results:
            if "prompt" in res:
                source_snippets.append(res["prompt"])

    # Step 4 — Sandbox Launch
    console.print("\n[dim]Step 4/8: Launching sandbox...[/]")
    sandbox_mgr = SandboxManager(profile, config)
    sandbox_info = await sandbox_mgr.launch()
    if sandbox_info.ready:
        console.print(f"  [bold green]LIVE[/] — Target running at [cyan]{sandbox_info.base_url}[/] (mode: {sandbox_info.mode})")
    else:
        console.print(f"  [bold red]FAILED[/] — Target did not respond at {sandbox_info.base_url}")
        console.print("  [red]Scan will still attempt probing but web findings may be limited.[/]")

    findings_bus = FindingsBus()

    # Real-time finding reporter
    def _on_finding(f):
        severity_color = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "blue", "Info": "dim"}.get(f.severity, "white")
        console.print(f"  [{severity_color}][{f.severity}][/] {f.vulnerability_type} on [cyan]{f.target_url}[/] (Agent: {f.agent})")

    findings_bus.subscribe(_on_finding)

    mcp_registry = None
    mcp_gateway = None
    if getattr(config, "use_mcp", False):
        console.print("\n[dim]Step 4.5/8: Building MCP tool registry...[/]")
        from raven_mcp.registry import ToolRegistry
        from raven_mcp.gateway import InternalGateway

        tool_registry = ToolRegistry()
        mcp_gateway = InternalGateway(tool_registry)
        tool_count = len(tool_registry.all_names())
        console.print(f"  [bold green]MCP READY[/] — {tool_count} tools registered: [cyan]{', '.join(tool_registry.all_names())}[/]")

    agent_1_findings = []
    agent_2_findings = []

    try:
        # Step 5 — Dual Agent Deployment
        console.print(f"\n[dim]Step 5/8: Deploying attack agents...[/]")
        agent1 = WebApiAgent(
            profile, sandbox_info, tool_plan["web_api"], findings_bus, provider,
            rag_context=rag_chunks, prioritized_techniques=prioritized_techniques,
            mcp_gateway=mcp_gateway, source_context=source_snippets
        )
        agent2 = AuthInfraAgent(
            profile, sandbox_info, tool_plan["auth_infra"], findings_bus, provider,
            rag_context=rag_chunks, prioritized_techniques=prioritized_techniques,
            mcp_gateway=mcp_gateway, source_context=source_snippets
        )


        if config.agent_mode == "web":
            console.print("  Running: [bold cyan]Agent 1 (Web/API)[/] only")
            agent_1_findings = await agent1.run()
        elif config.agent_mode == "auth":
            console.print("  Running: [bold blue]Agent 2 (Auth/Infra)[/] only")
            agent_2_findings = await agent2.run()
        else:
            console.print("  Running: [bold cyan]Agent 1 (Web/API)[/] + [bold blue]Agent 2 (Auth/Infra)[/] in parallel")
            res1, res2 = await asyncio.gather(
                agent1.run(),
                agent2.run(),
                return_exceptions=True
            )
            if isinstance(res1, list):
                agent_1_findings = res1
            else:
                console.print(f"  [red]Agent 1 error: {res1}[/]")
            if isinstance(res2, list):
                agent_2_findings = res2
            else:
                console.print(f"  [red]Agent 2 error: {res2}[/]")

    finally:
        # Step 8 — Sandbox Teardown
        console.print("\n[dim]Step 8/8: Tearing down sandbox...[/]")
        await sandbox_mgr.teardown()
        console.print("  [green]Sandbox terminated cleanly.[/]")

    all_findings = agent_1_findings + agent_2_findings

    # Step 6 — Chain Synthesis
    console.print(f"\n[dim]Step 6/8: Synthesizing attack chains...[/]")
    chains = _synthesize_chains(all_findings, agent_1_findings, agent_2_findings, profile, findings_bus)
    console.print(f"  [cyan]{len(chains)}[/] attack chains identified")

    # Step 7 — Risk Classification & LLM Executive Summary
    console.print("[dim]Step 7/8: Generating report...[/]")
    duration = time.time() - start_time
    score, label = RiskClassifier.calculate_score(all_findings, chains)

    # Generate LLM executive summary if provider is working
    exec_summary = _generate_executive_summary(provider, profile, all_findings, chains, score, label, llm_ok)

    remediations = []
    seen = set()
    for f in sorted(all_findings, key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(x.severity, 5)):
        if f.remediation and f.remediation not in seen:
            remediations.append(f.remediation)
            seen.add(f.remediation)

    report = FinalReport(
        target_path=str(path),
        project_profile=profile,
        sandbox_info=sandbox_info,
        scan_start=scan_start_iso,
        scan_end=datetime.now().isoformat(),
        duration_seconds=duration,
        agent_1_findings=agent_1_findings,
        agent_2_findings=agent_2_findings,
        attack_chains=chains,
        risk_score=score,
        risk_label=label,
        executive_summary=exec_summary,
        remediation_plan=remediations or ["No critical vulnerabilities detected. Continue monitoring."]
    )

    # Feedback Loop — persist successful patterns for self-improvement
    try:
        feedback.ingest(report)
    except Exception:
        pass

    return report


def _preflight_llm(provider: BaseProvider) -> bool:
    """Test if the LLM provider can actually respond."""
    try:
        if not provider.is_available():
            return False
        result = provider.analyze("Respond with OK.", "Test")
        return bool(result and len(result.strip()) > 0)
    except Exception:
        return False


def _synthesize_chains(
    all_findings, agent_1_findings, agent_2_findings, profile, bus
) -> list:
    """Build attack chains from cross-agent findings."""
    chains = []
    if len(all_findings) < 2:
        return chains

    # Group findings by endpoint
    from collections import defaultdict
    by_endpoint = defaultdict(list)
    for f in all_findings:
        by_endpoint[f.target_url].append(f)

    # Cross-agent chains
    a1_types = {f.vulnerability_type for f in agent_1_findings}
    a2_types = {f.vulnerability_type for f in agent_2_findings}

    if a1_types and a2_types:
        steps = []
        for f in agent_1_findings:
            steps.append(f"Agent 1: Exploited {f.vulnerability_type} on {f.target_url} via {f.method} {f.parameter}")
        for f in agent_2_findings:
            steps.append(f"Agent 2: Discovered {f.vulnerability_type} on {f.target_url}")

        chain = AttackChain(
            chain_name=f"Cross-Agent {profile.framework} Exploitation Chain",
            severity="Critical" if any(f.severity == "Critical" for f in all_findings) else "High",
            agent_1_finding_ids=[f.finding_id for f in agent_1_findings],
            agent_2_finding_ids=[f.finding_id for f in agent_2_findings],
            combined_impact="Web-layer vulnerabilities combined with infrastructure weaknesses create a multi-stage attack path from initial injection to credential theft and privilege escalation.",
            steps=steps,
            time_to_exploit="30-60 minutes"
        )
        chains.append(chain)

    # Endpoint-specific chains (multiple vulns on same endpoint)
    for ep, findings in by_endpoint.items():
        if len(findings) >= 2:
            chain = AttackChain(
                chain_name=f"Multi-Vector Attack on {ep.split('/')[-1] or 'root'}",
                severity="Critical" if any(f.severity == "Critical" for f in findings) else "High",
                agent_1_finding_ids=[f.finding_id for f in findings if f.agent == "web_api"],
                agent_2_finding_ids=[f.finding_id for f in findings if f.agent == "auth_infra"],
                combined_impact=f"Multiple vulnerabilities on the same endpoint ({ep}) enable layered exploitation.",
                steps=[f"{f.vulnerability_type} via {f.parameter}" for f in findings],
                time_to_exploit="15-30 minutes"
            )
            chains.append(chain)

    return chains


def _generate_executive_summary(
    provider, profile, findings, chains, score, label, llm_ok
) -> str:
    """Generate executive summary using LLM if available."""
    finding_summary = "\n".join([
        f"- [{f.severity}] {f.vulnerability_type} on {f.target_url} ({f.agent})"
        for f in findings
    ]) or "No vulnerabilities found."

    chain_summary = "\n".join([
        f"- [{c.severity}] {c.chain_name}: {c.combined_impact}"
        for c in chains
    ]) or "No attack chains identified."

    if llm_ok:
        try:
            response = provider.analyze(
                "You are a senior security consultant writing an executive summary for a penetration test report. "
                "Write exactly 3 paragraphs: (1) scope and methodology, (2) key findings, (3) risk assessment and recommendations. "
                "Be specific and actionable. Use professional language.",
                f"Target: {profile.language}/{profile.framework} application at {profile.path}\n"
                f"Risk Score: {score}/10.0 ({label})\n"
                f"Findings:\n{finding_summary}\n"
                f"Attack Chains:\n{chain_summary}"
            )
            if response and len(response.strip()) > 50:
                return response.strip()
        except Exception:
            pass

    # Fallback template
    vuln_count = len(findings)
    critical = sum(1 for f in findings if f.severity == "Critical")
    high = sum(1 for f in findings if f.severity == "High")
    return (
        f"An autonomous penetration test was conducted against the {profile.language}/{profile.framework} "
        f"application located at {profile.path}. The assessment covered {len(profile.detected_routes)} "
        f"identified endpoints using dual-agent concurrent attack methodology.\n\n"
        f"The scan discovered {vuln_count} confirmed vulnerabilities "
        f"({critical} Critical, {high} High severity) and {len(chains)} multi-stage attack chains. "
        + (f"The most severe findings include {', '.join(set(f.vulnerability_type for f in findings if f.severity in ('Critical', 'High')))}. " if critical + high > 0 else "")
        + f"\n\nOverall risk is assessed at {score}/10.0 ({label}). "
        f"Immediate remediation is recommended for all Critical and High severity findings."
    )
