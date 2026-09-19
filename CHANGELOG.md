# Changelog

## 3.1.0 - Adaptive engine rebuild

Complete rework around a target-agnostic, adaptive architecture (see README).

### Added
- Target intake/analysis producing a `TargetProfile`; scope derived from the target.
- Capability-based tool registry + MCP gateway (arg validation, scope, budget, timeout, normalization).
- Adaptive planner (re-plans every iteration; budget-aware; bounded optional LLM prioritization).
- Independent validator with SPA/route baselines, content signatures and secret redaction.
- Recovery controller with recorded decisions; honest coverage (`ASSESSED/PARTIALLY_ASSESSED/NOT_ASSESSED/NOT_APPLICABLE/BLOCKED`).
- Contextual knowledge (checklists, cases, validated lessons) and a learning pipeline gated on validated evidence.
- Simple menu CLI (Test / Setup / Help / Version / Exit); `--yes` for non-interactive authorization.

### Removed
- Legacy engine, engine models, capability manifests, adapters, orchestrator, sandbox, old reports/RAG (FAISS),
  readers, MCP subprocess servers, parallel web-scanner pipeline, unused tools (fuzzers, credential tester,
  process prober, external runners), PR-comment/badge CI helpers, and their tests.

### Fixed (defects in the previous engine, removed with it)
- Specialized agents were never executed (planner/agent identifier mismatch); tool calls used wrong parameter
  names/result shapes; every agent self-confirmed its findings; empty scans were scored "Clean";
  coverage marked unexecuted tests as tested; scope allowed every domain by default.


All notable changes to Raven will be documented in this file.

## [3.0.0] - 2026-09-16
### Added
- **Universal Target Resolution**: The new `TargetResolver` identifies targets dynamically (Web Apps, REST APIs, network services, binaries, repositories).
- **Deterministic Agent Routing**: `PlanningAgent` dynamically routes tasks to 7 specialized agents (e.g., `BinaryAssessmentAgent`, `NetworkAssessmentAgent`, `WebApiAgent`).
- **7 New Native MCP Tools**: The tool gateway expanded with `cli_fuzzer`, `protocol_prober`, `process_prober`, `banner_grabber`, `default_creds_tester`, `config_scanner`, and `permission_scanner`.
- **ValidationAgent**: Strict verification for all findings. Mandates reproducible `curl_poc` or `cli_poc`.
- **Honest Reporting**: Output reports explicitly disclose untested boundaries due to rate-limits or scope restrictions, avoiding false "no vulnerabilities found" claims.
- **RAG Memory Injection**: Integrates memory hints dynamically prior to the planning phase based on target profiles.
- **Atomic State Persistence**: Robust pause, resume, and crash recovery.
