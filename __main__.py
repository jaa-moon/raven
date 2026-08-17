"""
raven/__main__.py
-----------------
Allows Raven to be invoked as a module:
  python -m raven <args>

This is essential for CI/CD workflows where the tool is run via
  python -m raven scan . --rules --analyze
rather than a shell-installed script.
"""

from cli import app

if __name__ == "__main__":
    app()
