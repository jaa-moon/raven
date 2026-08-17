"""
ui/setup_wizard.py
------------------
Interactive first-run and reconfiguration wizard for Raven.

The wizard walks users through a clear four-step onboarding flow:

  Step 1 — Welcome screen explaining the tool and what will be configured.
  Step 2 — Provider selection (Ollama, OpenAI, Anthropic, Gemini, OpenRouter).
  Step 3 — Model selection (auto-detected for Ollama, curated list for cloud).
  Step 4 — Confirmation panel showing the chosen settings before saving.

Design principles
-----------------
- Rich panels with step indicators keep the user oriented at all times.
- Ollama models are auto-detected via the local daemon; cloud providers use
  provider-curated model lists so users always pick from valid options.
- API keys are masked on entry using Rich's password prompt.
- Errors render as styled Rich panels — never raw tracebacks.
- KeyboardInterrupt at any step exits cleanly with a helpful message.
- The wizard is side-effect free: it returns a config dict. The caller
  (cli.py) is responsible for persisting it via ConfigManager.
"""

from __future__ import annotations

import urllib.request
import urllib.error
import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.table import Table

from ui.banner import print_banner
from providers.factory import PROVIDER_DISPLAY_NAMES, PROVIDER_KEYS


# ── Internal helpers ──────────────────────────────────────────────────────────

def _step_header(console: Console, step: int, total: int, title: str) -> None:
    """
    Renders a step indicator rule above each wizard section.

    Displays e.g. "[Step 2/4] — Model Selection" in magenta.
    """
    console.print()
    label = f"[bold magenta][Step {step}/{total}][/] [magenta]— {title}[/]"
    console.print(Rule(label, style="magenta"))
    console.print()


def _info_line(console: Console, message: str) -> None:
    """Prints a dimmed informational line indented for wizard context."""
    console.print(f"  [dim]{message}[/]")


def _success_line(console: Console, message: str) -> None:
    """Prints a green success confirmation line."""
    console.print(f"  [bold green]✓[/] {message}")


def _warn_panel(console: Console, title: str, body: str) -> None:
    """Renders a yellow warning panel for non-fatal issues."""
    console.print(
        Panel(
            body,
            title=f"[bold yellow]{title}[/]",
            border_style="yellow",
            padding=(1, 3),
        )
    )


def _error_panel(console: Console, title: str, body: str) -> None:
    """Renders a red error panel for recoverable issues."""
    console.print(
        Panel(
            body,
            title=f"[bold red]{title}[/]",
            border_style="red",
            padding=(1, 3),
        )
    )


def _numbered_choice(
    console: Console,
    prompt_text: str,
    options: list[str],
    default_idx: int = 0,
    color: str = "white",
) -> int:
    """
    Displays a numbered list and prompts for a selection.

    Args:
        console:     Rich Console for output.
        prompt_text: Label shown above the input prompt.
        options:     List of option strings to display.
        default_idx: Zero-based index of the pre-selected default.
        color:       Rich color for option text (default "white").

    Returns:
        The zero-based index of the chosen option.
    """
    for i, opt in enumerate(options, start=1):
        is_default = (i - 1 == default_idx)
        style = "bold magenta" if is_default else color
        marker = " [dim](default)[/]" if is_default else ""
        console.print(f"  [bold magenta][{i}][/] [{style}]{opt}[/]{marker}")

    console.print()

    while True:
        raw = Prompt.ask(
            f"  [bold magenta]→[/] {prompt_text}",
            default=str(default_idx + 1),
            console=console,
        )
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        console.print(
            f"  [bold red]Invalid choice.[/] Enter a number between "
            f"[cyan]1[/] and [cyan]{len(options)}[/]."
        )


# ── Ollama auto-detection ─────────────────────────────────────────────────────

def _fetch_ollama_models(base_url: str = "http://localhost:11434") -> list[str]:
    """
    Queries the Ollama REST API for locally installed model names.

    Performs a direct HTTP request to avoid importing the optional Ollama SDK.
    Returns an empty list if Ollama is unreachable or returns unexpected data.

    Args:
        base_url: Base URL of the running Ollama daemon.

    Returns:
        List of model name strings, e.g. ["qwen2.5:7b", "llama3.1:8b"].
    """
    try:
        url = f"{base_url}/api/tags"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = data.get("models", [])
        return [m["name"] for m in models if isinstance(m, dict) and "name" in m]
    except Exception:
        return []


# ── Step 1: Welcome ───────────────────────────────────────────────────────────

def _step_welcome(console: Console, reconfigure: bool) -> None:
    """
    Displays the welcome panel explaining what the wizard will do.

    Args:
        console:     Rich Console for output.
        reconfigure: When True, shows a reconfiguration header instead.
    """
    if reconfigure:
        body = (
            "[bold magenta]Provider Reconfiguration[/]\n\n"
            "You are updating Raven's AI provider settings.\n"
            "Your existing configuration will be replaced when you finish.\n\n"
            "[dim]Config location: [bold]~/.raven/config.json[/][/]"
        )
        title = "[bold magenta]Reconfigure Raven[/]"
    else:
        body = (
            "[bold magenta]Welcome to Raven![/]\n\n"
            "Raven is an AI-powered Static Application Security Testing (SAST) tool.\n"
            "It combines deterministic rules, semantic search (RAG), and an LLM to\n"
            "find vulnerabilities in your codebase.\n\n"
            "This wizard will configure your AI provider in [bold]3 steps[/]:\n"
            "  [cyan]1.[/] Choose a provider  [dim](local Ollama or cloud API)[/]\n"
            "  [cyan]2.[/] Select a model\n"
            "  [cyan]3.[/] Confirm and save\n\n"
            "[dim]Config is saved to [bold]~/.raven/config.json[/] on this machine only.[/]"
        )
        title = "[bold magenta]First-Time Setup[/]"

    console.print(
        Panel(
            body,
            title=title,
            border_style="magenta",
            padding=(1, 4),
        )
    )


# ── Step 2: Provider selection ────────────────────────────────────────────────

def _step_select_provider(console: Console) -> str:
    """
    Prompts the user to choose an LLM provider from a numbered list.

    Returns:
        The provider key string, e.g. "ollama", "openai".
    """
    _step_header(console, 2, 4, "Choose Your LLM Provider")

    console.print(
        "  Raven uses a language model to analyze your code for vulnerabilities.\n"
        "  Choose a provider based on your environment:\n"
    )

    display_options = [PROVIDER_DISPLAY_NAMES[k] for k in PROVIDER_KEYS]
    idx = _numbered_choice(
        console,
        prompt_text="Select provider",
        options=display_options,
        default_idx=0,
    )

    chosen_key = PROVIDER_KEYS[idx]
    _success_line(console, f"Provider selected: [cyan]{PROVIDER_DISPLAY_NAMES[chosen_key]}[/]")
    return chosen_key


# ── Step 3a: Ollama model selection ──────────────────────────────────────────

def _step_configure_ollama(console: Console) -> dict:
    """
    Auto-detects installed Ollama models and prompts the user to pick one.

    Falls back to manual model name entry if Ollama is unreachable.

    Returns:
        Partial config dict: {"provider": "ollama", "model": "<name>"}.
    """
    _step_header(console, 3, 4, "Select Ollama Model")

    with console.status("[dim]Connecting to Ollama daemon...[/]", spinner="dots"):
        models = _fetch_ollama_models()

    if not models:
        _warn_panel(
            console,
            title="Ollama Unreachable",
            body=(
                "[yellow]Could not connect to Ollama at localhost:11434.[/]\n\n"
                "Make sure Ollama is running and you have at least one model installed.\n\n"
                "[dim]Install a model:  [bold]ollama pull qwen2.5:7b[/]\n"
                "Start the daemon:  [bold]ollama serve[/][/]"
            ),
        )
        console.print()
        model = Prompt.ask(
            "  [bold magenta]→[/] Enter model name manually",
            default="qwen2.5:7b",
            console=console,
        )
    else:
        console.print(f"  [bold green]✓[/] Found [bold]{len(models)}[/] installed model(s):\n")
        idx = _numbered_choice(
            console,
            prompt_text="Select model",
            options=models,
            default_idx=0,
            color="cyan",
        )
        model = models[idx]
        _success_line(console, f"Model selected: [cyan]{model}[/]")

    return {"provider": "ollama", "model": model}


# ── Step 3b: Cloud provider key + model ──────────────────────────────────────

# API key acquisition URLs per provider
_KEY_URLS: dict[str, str] = {
    "openai":     "https://platform.openai.com/api-keys",
    "anthropic":  "https://console.anthropic.com",
    "gemini":     "https://aistudio.google.com/apikey",
    "openrouter": "https://openrouter.ai/keys",
}

# Environment variable name for each provider (shown as a hint)
_KEY_ENV_VARS: dict[str, str] = {
    "openai":     "OPENAI_API_KEY",
    "anthropic":  "ANTHROPIC_API_KEY",
    "gemini":     "GOOGLE_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}


def _step_configure_cloud(console: Console, provider_key: str) -> dict:
    """
    Prompts for an API key (masked) and a model selection for cloud providers.

    Validates the connection before returning. If validation fails, the user
    can still save the configuration for later correction.

    Args:
        console:      Rich Console for output.
        provider_key: One of "openai", "anthropic", "gemini", "openrouter".

    Returns:
        Partial config dict: {"provider": ..., "model": ..., "api_key": ...}.
    """
    provider_name = PROVIDER_DISPLAY_NAMES.get(provider_key, provider_key.title())
    key_url       = _KEY_URLS.get(provider_key, "")
    key_env       = _KEY_ENV_VARS.get(provider_key, "API_KEY")

    _step_header(console, 3, 4, f"Configure {provider_name}")

    # Show where to get the key
    if key_url:
        _info_line(console, f"Get your API key at: [bold cyan]{key_url}[/]")
    _info_line(console, f"You can also set the [cyan]{key_env}[/] environment variable instead.")
    console.print()

    # Prompt for key (masked)
    while True:
        api_key = Prompt.ask(
            f"  [bold magenta]→[/] Enter your [cyan]{provider_name}[/] API key",
            password=True,
            console=console,
        )
        if api_key.strip():
            break
        _error_panel(console, "Empty Key", "API key cannot be empty. Please try again.")

    # Model selection
    _step_header(console, 3, 4, "Select Model")
    console.print(f"  Fetching available models for [cyan]{provider_name}[/]...\n")

    models: list[str] = []
    try:
        from providers.factory import get_provider
        temp_cfg = {"provider": provider_key, "model": "", "api_key": api_key}
        temp_provider = get_provider(temp_cfg)
        models = temp_provider.list_models()
    except Exception:
        models = []

    if not models:
        console.print(
            "  [yellow]Could not retrieve model list automatically.[/]\n"
            "  [dim]Enter the model name exactly as it appears in the provider's docs.[/]\n"
        )
        model = Prompt.ask(
            "  [bold magenta]→[/] Model name",
            console=console,
        )
    else:
        console.print(f"  Available models for [cyan]{provider_name}[/]:\n")
        idx = _numbered_choice(
            console,
            prompt_text="Select model",
            options=models,
            default_idx=0,
            color="cyan",
        )
        model = models[idx]
        _success_line(console, f"Model selected: [cyan]{model}[/]")

    # Validate connection
    console.print()
    with console.status(
        f"  [dim]Validating connection to [bold]{provider_name}[/]...[/]",
        spinner="dots",
    ):
        try:
            from providers.factory import get_provider
            live_provider = get_provider(
                {"provider": provider_key, "model": model, "api_key": api_key}
            )
            available = live_provider.is_available()
        except Exception:
            available = False

    if available:
        _success_line(console, f"Connection to [cyan]{provider_name} ({model})[/] verified!")
    else:
        _warn_panel(
            console,
            title="Connection Failed",
            body=(
                f"[yellow]Could not reach {provider_name}.[/]\n\n"
                "Check that your API key is correct and you have internet access.\n\n"
                "[dim]Your configuration will still be saved.\n"
                "You can update it anytime via [bold]Configure Providers[/] in the menu.[/]"
            ),
        )

    return {"provider": provider_key, "model": model, "api_key": api_key}


# ── Step 4: Confirmation ──────────────────────────────────────────────────────

def _step_confirm(console: Console, config: dict) -> bool:
    """
    Shows a summary panel of the chosen settings and asks for confirmation.

    Args:
        console: Rich Console for output.
        config:  The assembled config dict to display.

    Returns:
        True if the user confirms, False if they want to restart.
    """
    _step_header(console, 4, 4, "Confirm Configuration")

    provider_key  = config.get("provider", "")
    provider_label = PROVIDER_DISPLAY_NAMES.get(provider_key, provider_key)
    model          = config.get("model", "")
    raw_key        = config.get("api_key", "")

    # Mask key for display: show last 4 chars if long enough, else show dots
    if raw_key and len(raw_key) > 8:
        masked_key = f"{'•' * (len(raw_key) - 4)}{raw_key[-4:]}"
    elif raw_key:
        masked_key = "•" * len(raw_key)
    else:
        masked_key = "[dim](none — local provider)[/]"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold magenta", justify="right")
    summary.add_column(style="cyan")

    summary.add_row("Provider :", provider_label)
    summary.add_row("Model    :", model)
    if raw_key:
        summary.add_row("API Key  :", masked_key)

    console.print(
        Panel(
            summary,
            title="[bold magenta]Configuration Summary[/]",
            border_style="magenta",
            padding=(1, 4),
        )
    )
    console.print()

    confirmed = Confirm.ask(
        "  [bold magenta]→[/] Save this configuration?",
        default=True,
        console=console,
    )
    return confirmed


# ── Main wizard entry point ───────────────────────────────────────────────────

def run_setup_wizard(console: Console, reconfigure: bool = False) -> Optional[dict]:
    """
    Runs the full Raven setup wizard and returns the completed config dict.

    Prints the Raven banner, then walks the user through four steps:
      Step 1 — Welcome / purpose explanation.
      Step 2 — Provider selection.
      Step 3 — Model selection (Ollama auto-detect or cloud key + model list).
      Step 4 — Confirmation panel before saving.

    Args:
        console:     Rich Console instance for all output.
        reconfigure: When True, shows reconfiguration context instead of
                     the first-time welcome message.

    Returns:
        A complete config dict ready to pass to ConfigManager.save(), or
        None if the user cancelled via Ctrl+C or declined to save.
    """
    print_banner(console)

    try:
        # ── Step 1: Welcome ───────────────────────────────────────────────────
        _step_header(console, 1, 4, "Welcome to Raven")
        _step_welcome(console, reconfigure)

        # ── Step 2: Provider ──────────────────────────────────────────────────
        provider_key = _step_select_provider(console)

        # ── Step 3: Provider-specific configuration ───────────────────────────
        if provider_key == "ollama":
            config = _step_configure_ollama(console)
        else:
            config = _step_configure_cloud(console, provider_key)

        # ── Step 4: Confirm ───────────────────────────────────────────────────
        confirmed = _step_confirm(console, config)
        if not confirmed:
            console.print("\n  [yellow]Configuration not saved.[/] Re-run to configure.\n")
            return None

        # Save confirmation display
        console.print()
        console.print(
            Panel(
                "  [bold green]✓[/] [bold]Configuration saved successfully![/]\n\n"
                "  [dim]File: [bold]~/.raven/config.json[/]\n"
                "  You can change this anytime via [bold]Configure Providers[/] in the menu.[/]",
                title="[bold green]Setup Complete[/]",
                border_style="green",
                padding=(1, 4),
            )
        )
        console.print()

        return config

    except KeyboardInterrupt:
        console.print(
            "\n\n"
            "  [dim]Setup cancelled. Run [bold]raven[/] again whenever you're ready.[/]\n"
        )
        return None
