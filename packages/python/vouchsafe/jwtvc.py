"""Small shared VC-JWT helper for Ed25519 did:key credentials.

Used by the Content Receipt code (Pilastro 2). The mandate path (issue.py / verify.py)
predates this and is left untouched to avoid regressions; this captures the same
sign/verify shape so receipts don't reimplement it.
"""

from __future__ import annotations

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import did_to_public_key, issuer_did


def sign_vc_jwt(payload: dict, header: dict, key: Ed25519PrivateKey) -> str:
    """Sign ``payload`` as a compact EdDSA JWS with ``key`` (header gets kid=issuer DID)."""
    did = issuer_did(key)
    headers = {"kid": did, **header}
    return jwt.encode(payload, key, algorithm="EdDSA", headers=headers)


def verify_vc_jws(token: str) -> tuple[bool, dict | None, str | None]:
    """Verify a compact EdDSA JWS against the Ed25519 key named by its own ``iss`` (did:key).

    Returns ``(ok, payload, issuer_did)``. ``ok`` is False on a bad/none signature, an
    ``alg`` other than EdDSA, or a ``kid`` that disagrees with ``iss``. Raises ValueError
    only when the token is too malformed to read an issuer DID from.
    """
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        issuer = unverified["iss"]
        pub = did_to_public_key(issuer)
    except Exception as exc:  # noqa: BLE001 — malformed token
        raise ValueError(f"cannot read token: {exc}") from exc

    try:
        payload = jwt.decode(
            token, pub, algorithms=["EdDSA"],
            options={"verify_exp": False, "verify_nbf": False, "verify_aud": False},
        )
    except (jwt.InvalidSignatureError, InvalidSignature):
        return False, None, issuer
    except jwt.PyJWTError:
        return False, None, issuer

    header = jwt.get_unverified_header(token)
    if header.get("alg") != "EdDSA" or header.get("kid") not in (None, issuer):
        return False, None, issuer
    return True, payload, issuer
