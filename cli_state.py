"""
In-memory store mapping CLI token → enc_key hex.

Populated when the vault is unlocked, cleared when locked.
This is the bridge that lets CLI requests decrypt values without
sharing a browser session.
"""
from __future__ import annotations

_store: dict[str, str] = {}   # {cli_token: enc_key_hex}
_internal_key: str | None = None  # always set on unlock, regardless of CLI token


def set_key(token: str, enc_key_hex: str) -> None:
    """Called on every vault unlock."""
    global _internal_key
    _internal_key = enc_key_hex   # always store for internal use (watcher etc.)
    if token:
        _store[token] = enc_key_hex


def get_key(token: str) -> str | None:
    """Returns enc_key_hex if vault is unlocked, None if locked."""
    return _store.get(token)


def clear() -> None:
    """Called on vault lock — key is gone from memory."""
    global _internal_key
    _store.clear()
    _internal_key = None


def is_unlocked() -> bool:
    """Returns True if the vault is currently unlocked."""
    return _internal_key is not None


def get_key_direct() -> str | None:
    """Return enc_key_hex without needing the token (for internal use only)."""
    return _internal_key
