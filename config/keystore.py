"""
config/keystore.py
------------------
Machine-local API key encryption using Fernet symmetric encryption.

Design rationale
----------------
Storing API keys in plaintext in ~/.raven/config.json is convenient but leaves
keys exposed to any process that can read the file. This module adds a
lightweight encryption layer that ties the key to the local machine:

  - The Fernet key is derived from the machine hostname + CPU architecture
    using SHA-256, then base64-encoded to the 32-byte URL-safe format that
    Fernet requires.
  - This means the encrypted value in config.json is meaningless on any other
    machine (the derived Fernet key will be different), providing protection
    against naive file copies or cloud sync leaks.
  - Backward compatibility: if a stored value does NOT start with the "enc:"
    prefix, decrypt_key() returns it as-is. This ensures existing plaintext
    configs continue to work without a migration step.

Security note
-------------
This scheme is deliberately simple and local-only. It is NOT a substitute for
a system keychain (e.g. macOS Keychain, Windows Credential Manager, GNOME
Keyring). If enterprise-grade secret storage is required, the encrypt/decrypt
functions can be replaced with keychain calls while keeping the same interface.

Dependencies
------------
Requires the `cryptography` package:
    pip install cryptography
"""

from __future__ import annotations

import base64
import hashlib
import platform
from typing import Union


# ── Encryption prefix sentinel ────────────────────────────────────────────────

_ENC_PREFIX = "enc:"


# ── Machine-derived key ───────────────────────────────────────────────────────

def _derive_fernet_key() -> bytes:
    """
    Derives a Fernet-compatible 32-byte key from machine-specific identifiers.

    Uses SHA-256 of ``platform.node() + platform.machine()`` to produce a
    deterministic, machine-local secret. The raw digest is URL-safe base64
    encoded so that it satisfies Fernet's key format requirements exactly.

    Returns:
        32-byte URL-safe base64-encoded bytes suitable for ``Fernet(key)``.
    """
    machine_secret = (platform.node() + platform.machine()).encode("utf-8")
    digest = hashlib.sha256(machine_secret).digest()          # 32 raw bytes
    return base64.urlsafe_b64encode(digest)                   # Fernet key fmt


# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_key(plaintext: str) -> str:
    """
    Encrypts an API key string and returns a storable ciphertext string.

    The returned string is prefixed with ``"enc:"`` so that decrypt_key()
    can distinguish encrypted values from legacy plaintext ones.

    Args:
        plaintext: The raw API key string (e.g. ``"sk-proj-..."``)

    Returns:
        An encrypted string of the form ``"enc:gAAAAAB..."``.

    Raises:
        ImportError: If the ``cryptography`` package is not installed.
        Exception:   On any unexpected encryption failure.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for key encryption.\n"
            "Install it with:  pip install cryptography"
        ) from exc

    fernet = Fernet(_derive_fernet_key())
    token = fernet.encrypt(plaintext.encode("utf-8"))
    return _ENC_PREFIX + token.decode("utf-8")


def decrypt_key(stored: str) -> str:
    """
    Decrypts a stored API key string.

    If ``stored`` starts with the ``"enc:"`` prefix, the ciphertext portion is
    decrypted using the machine-derived Fernet key.  If it does NOT carry the
    prefix (i.e. it was saved by an older version of Raven), the value is
    returned unchanged for full backward compatibility.

    Args:
        stored: The value read from config.json's ``api_key`` field.

    Returns:
        The plaintext API key string.

    Raises:
        ImportError: If the ``cryptography`` package is not installed.
        cryptography.fernet.InvalidToken: If the token is corrupt or was
            encrypted on a different machine (key mismatch).
    """
    if not stored.startswith(_ENC_PREFIX):
        # Legacy plaintext value — return as-is for backward compatibility
        return stored

    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required to decrypt the stored API key.\n"
            "Install it with:  pip install cryptography"
        ) from exc

    ciphertext = stored[len(_ENC_PREFIX):]
    fernet = Fernet(_derive_fernet_key())
    return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


def is_encrypted(stored: Union[str, None]) -> bool:
    """
    Returns True if ``stored`` appears to be an encrypted value.

    Useful for display logic that wants to mask or label encrypted keys
    without actually decrypting them.

    Args:
        stored: The raw api_key value from config.json, or None.

    Returns:
        True if the value starts with the ``"enc:"`` prefix.
    """
    return isinstance(stored, str) and stored.startswith(_ENC_PREFIX)
