# Changelog

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
