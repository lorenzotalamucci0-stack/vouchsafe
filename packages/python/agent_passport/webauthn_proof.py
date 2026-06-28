"""Verify a WebAuthn assertion used as a *signature over a mandate*.

The human's passkey signs ``authenticatorData || SHA-256(clientDataJSON)`` where
``clientDataJSON.challenge == base64url(SHA-256(JCS(inner_mandate)))``. This binds the
exact mandate to a real, human-controlled authenticator.

Public keys are carried as SPKI DER (what ``navigator.credentials`` exposes via
``response.getPublicKey()``), with a COSE ``alg`` id telling us which scheme to use.
ES256 (-7) is the passkey default; Ed25519 (-8) and RS256 (-257) are also supported.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .jcs import b64url, b64url_decode, mandate_hash

# COSE algorithm identifiers.
ES256 = -7
EDDSA = -8
RS256 = -257


@dataclass
class ProofResult:
    ok: bool
    reason: str | None = None


def human_id_from_public_key(spki_b64url: str) -> str:
    """Stable, pseudonymous human root id derived from the passkey public key."""
    spki = b64url_decode(spki_b64url)
    return "urn:agentpassport:human:" + b64url(hashlib.sha256(spki).digest())


def _verify_signature(spki: bytes, alg: int, signature: bytes, signed: bytes) -> bool:
    pub = serialization.load_der_public_key(spki)
    try:
        if alg == ES256:
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return False
            pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == EDDSA:
            if not isinstance(pub, ed25519.Ed25519PublicKey):
                return False
            pub.verify(signature, signed)
        elif alg == RS256:
            if not isinstance(pub, rsa.RSAPublicKey):
                return False
            pub.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except InvalidSignature:
        return False
    return True


def verify_human_proof(inner_mandate: dict, human_proof: dict) -> ProofResult:
    """Verify the embedded WebAuthn assertion against the inner mandate."""
    try:
        authenticator_data = b64url_decode(human_proof["authenticatorData"])
        client_data_bytes = b64url_decode(human_proof["clientDataJSON"])
        signature = b64url_decode(human_proof["signature"])
        spki = b64url_decode(human_proof["publicKey"])
        alg = int(human_proof.get("alg", ES256))
    except (KeyError, ValueError, TypeError) as exc:
        return ProofResult(False, f"malformed humanProof: {exc}")

    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return ProofResult(False, f"invalid clientDataJSON: {exc}")

    if client_data.get("type") != "webauthn.get":
        return ProofResult(False, "clientDataJSON.type is not webauthn.get")

    expected_challenge = b64url(mandate_hash(inner_mandate))
    if client_data.get("challenge") != expected_challenge:
        return ProofResult(False, "challenge does not match mandate hash")

    signed = authenticator_data + hashlib.sha256(client_data_bytes).digest()
    if not _verify_signature(spki, alg, signature, signed):
        return ProofResult(False, "WebAuthn signature is invalid")

    return ProofResult(True)
