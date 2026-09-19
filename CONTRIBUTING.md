# Contributing to Raven

First off, thank you for considering contributing to Raven! It's people like you that make Raven an excellent tool for the security community.

## Development Setup
1. Clone the repository
2. Create a virtual environment (`python -m venv venv`)
3. Install dependencies (`pip install -r requirements.txt`)
4. Run tests before submitting a PR (`python run_tests.py`)

## Pull Request Process
1. Ensure your code passes all existing tests.
2. If you are adding a new feature, please include tests demonstrating the functionality.
3. Keep architectural changes minimal unless previously discussed in an Issue.
4. Update the README.md with details of changes to the interface or significant new features.

## Architecture Guidelines
Raven employs an adaptive, multi-agent architecture (v3.0.0). When contributing:
- **Tools**: All new security tools should be registered via the MCP Gateway (`raven_mcp/`) and implement standard timeout and structured JSON return handling.
- **Agents**: Agents should interact strictly through the unified Gateway and share findings via the common event bus.
- **Validation**: Any new vulnerability discovery logic must synthesize a reproducible Proof of Concept (`curl_poc` or `cli_poc`) for validation.

Thank you!
