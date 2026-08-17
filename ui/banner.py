"""
ui/banner.py
------------
Renders the Raven startup banner.

The banner uses Rich markup for purple/magenta styling. It includes a Unicode
detection fallback: if the terminal reports no Unicode support (e.g. legacy
Windows cmd.exe with a non-UTF-8 code page), a compact plain-text header
is shown instead of the ASCII art block.
"""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.text import Text

# ── ASCII art block ───────────────────────────────────────────────────────────

_BANNER_ART = r"""
██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝"""

_VERSION = "  v0.5.0"

# Fallback for terminals without Unicode block-drawing support
_PLAIN_BANNER = """
  ____      _       _    _____ __  __
 |  _ \    / \    | |  | ____|  \/  |
 | |_) |  / _ \   | |  |  _| | |\/| |
 |  _ <  / ___ \  | |__| |___| |  | |
 |_| \_\/_/   \_\ |____|_____|_|  |_|
"""


def _supports_unicode() -> bool:
    """
    Returns True if the current terminal can display Unicode block characters.
    Checks stdout encoding and the TERM / WT_SESSION environment variables.
    """
    # Windows Terminal sets WT_SESSION; PowerShell and VS Code are fine
    if os.environ.get("WT_SESSION"):
        return True
    # VS Code integrated terminal
    if os.environ.get("TERM_PROGRAM") in ("vscode",):
        return True
    # Check stdout encoding
    encoding = getattr(sys.stdout, "encoding", None) or ""
    if encoding.lower().replace("-", "") in ("utf8", "utf16"):
        return True
    # Linux/macOS terminals almost always support Unicode
    if os.name != "nt":
        return True
    return False


def print_banner(console: Console) -> None:
    """
    Prints the Raven startup banner to the given Rich console.

    Uses full ASCII-art block characters when the terminal supports Unicode,
    falls back to a compact plain-ASCII header on legacy Windows terminals.
    """
    console.print()  # Leading blank line

    if _supports_unicode():
        try:
            # Render each line of the banner in vivid magenta/purple
            art_text = Text(_BANNER_ART, style="bold #5d3fd3")
            console.print(art_text)
            console.print(Text(_VERSION, style="dim #5d3fd3"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            # Fall back if terminal truly can't render block chars
            console.print(_PLAIN_BANNER, style="bold #5d3fd3")
            console.print(_VERSION, style="dim")
    else:
        # Plain ASCII fallback for legacy terminals
        console.print(_PLAIN_BANNER, style="bold #5d3fd3")
        console.print(_VERSION, style="dim")

    console.print()  # Trailing blank line
