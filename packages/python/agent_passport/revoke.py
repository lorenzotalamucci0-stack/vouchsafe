"""Revoke a mandate via a local status store."""

from __future__ import annotations

from .status import StatusStore


def revoke(mandate_id: str, store: StatusStore) -> bool:
    """Flip a mandate to revoked. Returns False if the mandate is unknown."""
    return store.revoke(mandate_id)
