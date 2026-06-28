"""Canonical JSON (JCS-like, RFC 8785) + SHA-256 hashing for mandates.

We rely on `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
For the mandate data model (strings, ints, bools, null, arrays, objects — no floats)
this is byte-equivalent to RFC 8785 JCS, and any verifier in any language can reproduce
the same bytes. Floats are rejected to avoid number-canonicalization divergence.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floats are not allowed in a canonical mandate (use integers/strings)")
    if isinstance(value, dict):
        for v in value.values():
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)


def canonicalize(obj: Any) -> bytes:
    """Return the canonical UTF-8 JSON encoding of ``obj``."""
    _reject_floats(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def mandate_hash(inner_mandate: dict) -> bytes:
    """The 32-byte challenge: SHA-256 over the canonical inner mandate."""
    return sha256(canonicalize(inner_mandate))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
