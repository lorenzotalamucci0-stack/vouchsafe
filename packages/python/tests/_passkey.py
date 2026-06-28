"""A software 'passkey' that signs a mandate the way a real WebAuthn authenticator would.

Lets us exercise the WebAuthn-as-signature path (ES256 / EC P-256, the passkey default)
with no physical authenticator. The E2E browser test uses a real CDP virtual authenticator;
this is the fast unit-level stand-in.
"""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vouchsafe.jcs import b64url, mandate_hash


class SoftwarePasskey:
    def __init__(self, rp_id: str = "localhost", origin: str = "http://localhost:8000"):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.rp_id = rp_id
        self.origin = origin
        self.credential_id = b"software-passkey-credential-id"

    @property
    def spki_b64url(self) -> str:
        spki = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b64url(spki)

    def sign_mandate(self, inner_mandate: dict, *, corrupt: bool = False, flags: bytes = b"\x05") -> dict:
        challenge = b64url(mandate_hash(inner_mandate))
        if corrupt:
            challenge = b64url(b"not-the-real-challenge-bytes-000")
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": self.origin},
            separators=(",", ":"),
        ).encode("utf-8")

        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        # flags default 0x05 = UP (0x01) | UV (0x04); tests can pass 0x00 to omit User Present.
        sign_count = b"\x00\x00\x00\x00"
        authenticator_data = rp_id_hash + flags + sign_count

        signed = authenticator_data + hashlib.sha256(client_data).digest()
        signature = self._key.sign(signed, ec.ECDSA(hashes.SHA256()))

        return {
            "type": "WebAuthnAssertion2026",
            "credentialId": b64url(self.credential_id),
            "authenticatorData": b64url(authenticator_data),
            "clientDataJSON": b64url(client_data),
            "signature": b64url(signature),
            "publicKey": self.spki_b64url,
            "alg": -7,
        }
