"""Dev-only helpers to mint a passport WITHOUT a browser / real passkey.

⚠️ DEV / EXAMPLES / TESTS ONLY. This bypasses the human: it signs the mandate with a software
key standing in for a WebAuthn authenticator, so there is NO real human authorization. Never use
it in production — there a real person signs with their passkey through the issuer UI (see
`server/`). It exists so examples and the Claude Code recipe run end-to-end with one command.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .issue import issue
from .jcs import b64url, mandate_hash
from .keys import generate_issuer_key, issuer_did
from .mandate import build_inner_mandate
from .revoke import revoke as _revoke
from .status import StatusStore, store_status_resolver
from .webauthn_proof import human_id_from_public_key


class DevPasskey:
    """A software stand-in for a WebAuthn authenticator (ES256 / EC P-256). DEV ONLY."""

    def __init__(self, rp_id: str = "localhost", origin: str = "http://localhost"):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.rp_id = rp_id
        self.origin = origin
        self.credential_id = b"dev-passkey-credential"

    @property
    def spki_b64url(self) -> str:
        spki = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b64url(spki)

    def sign_mandate(self, inner: dict) -> dict:
        challenge = b64url(mandate_hash(inner))
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": self.origin},
            separators=(",", ":"),
        ).encode("utf-8")
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + b"\x05" + b"\x00\x00\x00\x00"
        signature = self._key.sign(auth_data + hashlib.sha256(client_data).digest(),
                                   ec.ECDSA(hashes.SHA256()))
        return {
            "type": "WebAuthnAssertion2026",
            "credentialId": b64url(self.credential_id),
            "authenticatorData": b64url(auth_data),
            "clientDataJSON": b64url(client_data),
            "signature": b64url(signature),
            "publicKey": self.spki_b64url,
            "alg": -7,
        }


@dataclass
class DevPassport:
    token: str
    issuer_did: str
    agent_key: Ed25519PrivateKey
    agent_did: str
    mandate_id: str
    resolver: object  # status resolver bound to the in-process store
    store: StatusStore

    def revoke(self) -> bool:
        return _revoke(self.mandate_id, self.store)


def dev_issue(
    *,
    scope: list[str],
    status_path,
    agent_key: Ed25519PrivateKey | None = None,
    agent_name: str = "Dev Agent",
    ttl_seconds: int = 3600,
    status_base_url: str = "http://localhost",
) -> DevPassport:
    """Mint a fully-valid passport in one call. DEV ONLY — no real human signs."""
    issuer_key = generate_issuer_key()
    agent_key = agent_key or generate_issuer_key()
    passkey = DevPasskey()
    human_id = human_id_from_public_key(passkey.spki_b64url)
    inner = build_inner_mandate(
        issuer_did=issuer_did(issuer_key),
        agent_id=issuer_did(agent_key),
        agent_name=agent_name,
        scope=scope,
        human_id=human_id,
        ttl_seconds=ttl_seconds,
        status_base_url=status_base_url,
    )
    token = issue(inner, passkey.sign_mandate(inner), issuer_key)
    store = StatusStore(status_path)
    store.register(inner["id"])
    return DevPassport(
        token=token, issuer_did=issuer_did(issuer_key), agent_key=agent_key,
        agent_did=issuer_did(agent_key), mandate_id=inner["id"],
        resolver=store_status_resolver(store), store=store,
    )
