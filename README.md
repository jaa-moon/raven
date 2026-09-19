# Raven: Autonomous Pentesting Agent

Raven is an autonomous AI penetration-testing framework capable of executing complex security assessments. 
Instead of relying on rigid, pre-defined rules, Raven dynamically inspects its targets and orchestrates a team of specialized AI agents using a Model Context Protocol (MCP) gateway to uncover vulnerabilities.

**Version:** 3.0.0 (Adaptive Agentic Architecture)

> ⚠️ **Disclaimer:** Raven is designed strictly for authorized security testing. You must have explicit permission to probe the targets you assess. Raven can execute active payloads and generate significant traffic. See [SECURITY.md](SECURITY.md) for full terms.

---

## 🎯 Key Features

- **Universal Target Resolution**: Assess web applications, REST/GraphQL APIs, raw network services (`host:port`), local executables, and source code repositories.
- **7 Specialized Agents**: Includes deep-inspection agents for Web/API, Network, Binary, Configuration, Auth/Identity, Source Code, and Finding Validation.
- **20 MCP Security Tools**: Features a sandboxed gateway exposing capabilities like protocol probing, CLI fuzzing, banner grabbing, directory fuzzing, SQLi testing, and more.
- **Honest Coverage Reporting**: Raven transparently tracks what it *actually* tested. If boundaries are blocked by rate limits or WAFs, Raven explicitly declares them as untested instead of falsely claiming "no vulnerabilities found."
- **Strict Finding Validation**: Vulnerabilities are never blindly accepted. Raven synthesizes reproducible `curl_poc` or `cli_poc` commands and attempts to execute them dynamically to confirm impact.
- **Atomic State Persistence**: Resilient to crashes and pauses. The framework maintains a persistent `AssessmentState`, tracking active agent plans and rejected hypotheses.

## ⚙️ Architecture

Raven operates in a 12-step deterministic pipeline:
1. **Target Resolution**: Auto-classifies the target type.
2. **Scope Validation**: Checks authorization and boundary limits.
3. **Reconnaissance**: Initial mapping, banner grabbing, process inspection.
4. **Asset Graph Synthesis**: Builds an internal map of attack surfaces.
5. **Capability Discovery**: Selects safe tools based on the defined scope.
6. **RAG Knowledge Retrieval**: Injects target-specific exploit knowledge.
7. **Adaptive Planning**: Deterministically routes execution to specialized agents.
8. **Parallel Execution**: Agents execute attacks via the MCP gateway.
9. **Validation**: Findings are verified with active reproducible PoCs.
10. **Risk Correlation**: Cross-references findings to build attack chains.
11. **Reporting**: Generates the final Markdown assessment.

## 🚀 Installation

Ensure you have Python 3.10+ installed.

```bash
git clone https://github.com/your-org/raven.git
cd raven
python -m venv venv
# Windows: venv\Scripts\activate
# Unix/macOS: source venv/bin/activate
pip install -r requirements.txt
```

## 🛠️ Usage

Raven operates primarily through its CLI interface.

### Running an Assessment
```bash
python -m cli.app assess <target> --depth [quick|standard|deep]
```
*`<target>` can be a URL, IP, `host:port`, local path, or binary.*

### Configuration
Raven stores its configuration at `~/.raven/config.json`.
See `config.example.json` for the expected schema. 
Raven defaults to using a local `ollama` provider with `qwen2.5:7b` for completely offline execution, but easily scales to Anthropic, OpenAI, or Gemini.

## 🤝 Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
