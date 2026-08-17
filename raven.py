"""
raven.py
--------
Single main entry point for Raven CLI tool.
"""

from __future__ import annotations

import sys
from cli.app import app

if __name__ == "__main__":
    app()
