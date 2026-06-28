"""Issue a passport token (VC-JWT) from an inner mandate + human proof."""

from __future__ import annotations

from datetime import datetime, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import InvalidProofError
from .keys import issuer_did
from .webauthn_proof import verify_human_proof


def _epoch(rfc3339: str) -> int:
    dt = datetime.strptime(rfc3339, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def issue(
    inner_mandate: dict,
    human_proof: dict,
    issuer_key: Ed25519PrivateKey,
    *,
    verify_proof: bool = True,
) -> str:
    """Wrap ``inner_mandate`` + ``human_proof`` into a signed VC-JWT passport token.

    The inner mandate MUST be the exact object whose hash was used as the WebAuthn
    challenge (see ``build_inner_mandate``). By default the human proof is verified
    before signing so an issuer never mints a token over an invalid human signature.
    """
    if verify_proof:
        result = verify_human_proof(inner_mandate, human_proof)
        if not result.ok:
            raise InvalidProofError(result.reason or "invalid human proof")

    did = issuer_did(issuer_key)
    if inner_mandate.get("issuer") != did:
        raise ValueError("inner_mandate.issuer does not match the issuer key")

    credential = dict(inner_mandate)
    credential["humanProof"] = human_proof

    payload = {
        "iss": did,
        "jti": inner_mandate["id"],
        "sub": inner_mandate["credentialSubject"]["id"],
        "nbf": _epoch(inner_mandate["validFrom"]),
        "exp": _epoch(inner_mandate["validUntil"]),
        "vc": credential,
    }
    return jwt.encode(
        payload,
        issuer_key,
        algorithm="EdDSA",
        headers={"typ": "vc+jwt", "kid": did},
    )
