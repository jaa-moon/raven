"""
adapters/target_adapters/binary_adapter.py
-----------------------------------------
Target adapter for native binaries and CLI applications.
"""

from __future__ import annotations

import os
from pathlib import Path
from engine_models.target import Target, TargetType


class BinaryTargetAdapter:
    """Adapts compiled executables, CLI tools, and native binaries into Target models."""

    EXECUTABLE_EXTENSIONS = {".exe", ".bin", ".elf", ".so", ".dll", ".dylib", ".sh", ".bat", ".cmd"}

    @classmethod
    def can_handle(cls, raw_input: str) -> bool:
        clean = raw_input.strip()
        if not os.path.exists(clean):
            return False
        if os.path.isdir(clean):
            return False
        p = Path(clean)
        # Check executable permission or known executable extension
        if p.suffix.lower() in cls.EXECUTABLE_EXTENSIONS or os.access(clean, os.X_OK):
            return True
        # Check if file has binary content (ELF, PE magic numbers)
        try:
            with open(clean, "rb") as f:
                header = f.read(4)
                if header.startswith(b"\x7fELF") or header.startswith(b"MZ"):
                    return True
        except Exception:
            pass
        return False

    @classmethod
    def adapt(cls, raw_input: str) -> Target:
        p = Path(raw_input.strip()).resolve()
        return Target(
            raw_input=raw_input,
            target_type=TargetType.NATIVE_BINARY,
            entrypoints=[str(p)],
            metadata={
                "absolute_path": str(p),
                "file_size": p.stat().st_size if p.exists() else 0,
                "is_executable": os.access(str(p), os.X_OK),
            },
        )
