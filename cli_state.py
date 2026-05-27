"""
In-memory store mapping CLI token → enc_key hex.

Populated when the vault is unlocked, cleared when locked.
This is the bridge that lets CLI requests decrypt values without
sharing a browser session.
"""
from __future__ import annotations

_store: dict[str, str] = {}   # {cli_token: enc_key_hex}


def set_key(token: str, enc_key_hex: str) -> None:
    """Called on every vault unlock."""
    if token:
        _store[token] = enc_key_hex


def get_key(token: str) -> str | None:
    """Returns enc_key_hex if vault is unlocked, None if locked."""
    return _store.get(token)


def clear() -> None:
    """Called on vault lock — key is gone from memory."""
    _store.clear()


def is_unlocked() -> bool:
    """Returns True if the vault is currently unlocked."""
    return len(_store) > 0


def get_key_direct() -> str | None:
    """Return enc_key_hex without needing the token (for internal use only)."""
    if _store:
        return next(iter(_store.values()))
    return None
