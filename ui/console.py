"""
ui/console.py
-------------
Singleton Rich Console instance shared across all Raven UI modules.

Design rationale
----------------
A single Console() instance ensures all Rich output is coordinated: progress
bars, panels, tables, and live displays never clobber each other because Rich
routes everything through one internal buffer. Modules that each create their
own Console() can produce interleaved, corrupted output — especially when a
progress bar is active.

Usage:
    from ui.console import console

    console.print("[bold magenta]Hello from Raven[/]")
"""

from __future__ import annotations

from rich.console import Console

#: The single application-wide Rich Console. Import this everywhere.
console: Console = Console()
