"""
tools/cli_fuzzer.py
-------------------
Command-line boundary testing and fuzzer tool for Raven.

Executes CLI binaries or scripts with boundary arguments and special payloads
to check for crashes, unhandled exceptions, memory errors, or command leaks.
Always enforces subprocess timeouts and safety limits.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from typing import Any, Dict, List, Optional


class CLIFuzzer:
    """Tests CLI applications with boundary inputs and edge cases."""

    DEFAULT_TEST_PAYLOADS = [
        # Boundary lengths
        "A" * 500,
        "A" * 2000,
        # Format strings
        "%s%s%s%s%s%s%s%s",
        "%x%x%x%x",
        # Special punctuation / command injection checks (inert)
        "';--",
        "\" || true #",
        "$(echo raven)",
        "`echo raven`",
        # Path traversal inputs
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        # Null bytes & control chars
        "test\x00extra",
        "-1",
        "9999999999999999999999999999",
    ]

    def __init__(self, binary_path: str, timeout: float = 5.0) -> None:
        self.binary_path = binary_path
        self.timeout = timeout

    async def fuzz(
        self,
        base_args: Optional[List[str]] = None,
        custom_payloads: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute the target binary across boundary inputs."""
        args_prefix = base_args or []
        payloads = custom_payloads or self.DEFAULT_TEST_PAYLOADS
        crashes: List[Dict[str, Any]] = []
        tests_run = 0

        if not os.path.exists(self.binary_path):
            return {
                "binary": self.binary_path,
                "error": f"Binary not found: {self.binary_path}",
                "tests_run": 0,
                "crashes": [],
            }

        for payload in payloads:
            tests_run += 1
            cmd = [self.binary_path] + args_prefix + [payload]
            try:
                # Run with timeout
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
                    stdout = stdout_b.decode("utf-8", errors="replace")[:1000]
                    stderr = stderr_b.decode("utf-8", errors="replace")[:1000]
                    returncode = proc.returncode
                except asyncio.TimeoutError:
                    proc.kill()
                    returncode = -9
                    stdout, stderr = "", "Process killed due to timeout (potential hang/DoS)"

                # Check for crash indicators
                is_crash = False
                reason = ""

                # Signal crashes (segfault, abort, bus error)
                if returncode in (-11, -6, -4, 139, 134):
                    is_crash = True
                    reason = f"Fatal signal exit code: {returncode}"
                # Unhandled stack traces
                elif "Traceback (most recent call last):" in stderr:
                    is_crash = True
                    reason = "Unhandled Python exception trace in stderr"
                elif "panic:" in stderr or "Segmentation fault" in stderr:
                    is_crash = True
                    reason = "Panic or Segmentation Fault in stderr"
                elif "Assertion failed:" in stderr:
                    is_crash = True
                    reason = "Assertion failure in stderr"

                if is_crash:
                    crashes.append({
                        "payload": payload[:50],
                        "returncode": returncode,
                        "reason": reason,
                        "stderr_sample": stderr[:200],
                    })

            except FileNotFoundError:
                return {
                    "binary": self.binary_path,
                    "error": "Binary executable not found",
                    "tests_run": tests_run,
                    "crashes": [],
                }
            except PermissionError:
                return {
                    "binary": self.binary_path,
                    "error": "Permission denied executing binary",
                    "tests_run": tests_run,
                    "crashes": [],
                }
            except Exception as e:
                pass

        return {
            "binary": self.binary_path,
            "tests_run": tests_run,
            "crashes_detected": len(crashes),
            "crashes": crashes,
            "vulnerable": len(crashes) > 0,
        }


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def fuzz(
    binary_path: str,
    base_args: Optional[List[str]] = None,
    custom_payloads: Optional[List[str]] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Gateway-callable wrapper for CLIFuzzer."""
    fuzzer = CLIFuzzer(binary_path=binary_path, timeout=timeout)
    return await fuzzer.fuzz(base_args=base_args, custom_payloads=custom_payloads)
