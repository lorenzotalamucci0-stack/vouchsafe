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


# Restricted JSON profile (I-JSON-like) so Python and JS produce identical bytes:
#  - no floats (number-canonicalization would diverge),
#  - integers only within the IEEE-754 safe range (JS Number can't represent more
#    without switching to exponential notation, breaking the cross-language hash),
#  - object KEYS must stay within the Basic Multilingual Plane (Python sorts keys by
#    Unicode code point, JS String#sort by UTF-16 code unit — they agree only inside
#    the BMP). String VALUES may be any Unicode (both emit identical UTF-8).
_MAX_SAFE_INT = 2**53 - 1


def _check_json(value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise ValueError("floats are not allowed in a canonical mandate (use integers/strings)")
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise ValueError("integers must be within the IEEE-754 safe range for cross-language hashing")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            if any(ord(ch) > 0xFFFF for ch in k):
                raise ValueError("object keys must stay within the Basic Multilingual Plane")
            _check_json(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _check_json(v)


def canonicalize(obj: Any) -> bytes:
    """Return the canonical UTF-8 JSON encoding of ``obj`` (restricted JSON profile)."""
    _check_json(obj)
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
