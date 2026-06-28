"""Mint a passport token (Python SDK) and print it as JSON, for the JS interop test."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from vouchsafe import (  # noqa: E402
    build_inner_mandate,
    generate_issuer_key,
    human_id_from_public_key,
    issue,
    issuer_did,
)
from _passkey import SoftwarePasskey  # noqa: E402

key = generate_issuer_key()
passkey = SoftwarePasskey()
inner = build_inner_mandate(
    issuer_did=issuer_did(key),
    agent_id="did:key:zAgentInterop",
    agent_name="Interop Bot",
    scope=["read:calendar", "book:flights"],
    human_id=human_id_from_public_key(passkey.spki_b64url),
    ttl_seconds=600,
    status_base_url="http://localhost:8090",
)
proof = passkey.sign_mandate(inner)
token = issue(inner, proof, key)

print(json.dumps({
    "token": token,
    "issuerDid": issuer_did(key),
    "mandateId": inner["id"],
    "scope": inner["credentialSubject"]["scope"],
}))
