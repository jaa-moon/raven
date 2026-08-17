"""
config/manager.py
-----------------
Manages Raven's persistent user configuration stored at ~/.raven/config.json.

Design decisions
----------------
- Location: ~/.raven/ — follows the XDG Base Directory convention on Linux/macOS
  and the equivalent home directory convention on Windows.
- Format: JSON — human-readable, no binary encoding, easily debuggable.
- Atomic writes: we write to a temp file then rename to avoid corruption if
  the process is interrupted mid-write.
- API key encryption: the api_key field is encrypted at rest using Fernet
  symmetric encryption (see config/keystore.py). The ciphertext is prefixed
  with "enc:" so legacy plaintext configs are detected and returned as-is
  without a migration step.
- File permissions: restricted to 600 (owner read/write only) on Unix systems,
  the same approach used by AWS CLI, GitHub CLI, and Heroku CLI.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Optional


class ConfigManager:
    """
    Owns Raven's user configuration file at ~/.raven/config.json.

    The manager transparently encrypts any ``api_key`` field when saving
    and decrypts it when loading, so all callers always work with plaintext
    key values regardless of how they are stored on disk.

    If the ``cryptography`` package is not installed, encryption is silently
    skipped and the key is stored in plaintext (preserving old behaviour).

    Usage::

        mgr = ConfigManager()
        if mgr.is_configured():
            cfg = mgr.load()          # api_key is already decrypted here
        else:
            mgr.save({"provider": "ollama", "model": "qwen2.5:7b"})
    """

    CONFIG_DIR:  Path = Path.home() / ".raven"
    CONFIG_PATH: Path = CONFIG_DIR / "config.json"

    # ── Public interface ──────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """
        Returns True if a config file exists and contains a ``provider`` key.

        A missing or empty config triggers the first-run setup wizard.
        """
        if not self.CONFIG_PATH.exists():
            return False
        data = self.load()
        return data is not None and bool(data.get("provider"))

    def load(self) -> Optional[dict]:
        """
        Loads the config dict and decrypts the ``api_key`` field if present.

        Returns None if the file is missing or corrupt.  Never raises — callers
        should treat None as "not configured".

        The returned dict always contains a plaintext ``api_key`` value so
        callers never need to import keystore themselves.
        """
        if not self.CONFIG_PATH.exists():
            return None
        try:
            text = self.CONFIG_PATH.read_text(encoding="utf-8")
            data = json.loads(text)
        except (json.JSONDecodeError, OSError):
            return None

        # Decrypt api_key if it carries the "enc:" prefix
        raw_key = data.get("api_key")
        if raw_key:
            try:
                from config.keystore import decrypt_key
                data["api_key"] = decrypt_key(raw_key)
            except Exception:
                # Decryption failed (wrong machine, corrupt token, missing dep).
                # Return the raw value rather than crashing — the provider call
                # will fail with an auth error, which is friendlier than a crash.
                pass

        return data

    def save(self, config: dict) -> None:
        """
        Encrypts the ``api_key`` field (if present) and atomically writes the
        config dict to ``~/.raven/config.json``.

        Creates the directory if it does not exist.
        Sets file permissions to 600 on Unix systems.

        Args:
            config: The config dict to persist.  ``api_key``, if present,
                    should be the plaintext key — this method handles encryption.
        """
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        # Work on a copy so we don't mutate the caller's dict
        data = dict(config)

        # Encrypt api_key before writing to disk
        raw_key = data.get("api_key")
        if raw_key:
            try:
                from config.keystore import encrypt_key, is_encrypted
                if not is_encrypted(raw_key):
                    data["api_key"] = encrypt_key(raw_key)
            except Exception:
                # cryptography not installed or encryption failed — store as-is.
                # The plaintext fallback means the tool stays functional even
                # without the extra dependency.
                pass

        # Atomic write: write to temp file, then rename to final path
        tmp_path = self.CONFIG_PATH.with_suffix(".tmp")
        try:
            text = json.dumps(data, indent=2, ensure_ascii=False)
            tmp_path.write_text(text, encoding="utf-8")

            # Restrict permissions before rename so the final file is secure
            if os.name != "nt":  # Unix/macOS only
                os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)

            tmp_path.replace(self.CONFIG_PATH)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    def get(self, key: str, default: Any = None) -> Any:
        """
        Convenience method: load config and return a specific key's value.

        Args:
            key:     Config dict key to retrieve.
            default: Value returned when the key is absent or config is None.
        """
        data = self.load()
        if data is None:
            return default
        return data.get(key, default)

    def update(self, key: str, value: Any) -> None:
        """
        Updates a single key in the config without overwriting other keys.

        Performs a read-modify-write cycle. Thread safety is best-effort via
        the atomic rename in save().

        Args:
            key:   Config dict key to update.
            value: New value to set.
        """
        data = self.load() or {}
        data[key] = value
        self.save(data)

    def delete(self) -> None:
        """Removes the config file entirely (used for reset / reconfigure flows)."""
        if self.CONFIG_PATH.exists():
            self.CONFIG_PATH.unlink()

    def display_path(self) -> str:
        """Returns the config file path as a string for display in the UI."""
        return str(self.CONFIG_PATH)
