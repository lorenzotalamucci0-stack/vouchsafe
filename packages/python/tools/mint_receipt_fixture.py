"""Mint a Content Receipt (Python SDK) and print it as JSON, for the JS interop test."""

import base64
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
    sign_receipt,
)
from _passkey import SoftwarePasskey  # noqa: E402

issuer_key = generate_issuer_key()
agent_key = generate_issuer_key()
passkey = SoftwarePasskey()
content = b"Draft post: Vouchsafe ships verifiable, revocable mandates. \xf0\x9f\xa4\x96"

inner = build_inner_mandate(
    issuer_did=issuer_did(issuer_key),
    agent_id=issuer_did(agent_key),
    agent_name="Interop Bot",
    scope=["read:calendar", "post:linkedin"],
    human_id=human_id_from_public_key(passkey.spki_b64url),
    ttl_seconds=600,
    status_base_url="http://localhost:8090",
)
token = issue(inner, passkey.sign_mandate(inner), issuer_key)
receipt = sign_receipt(content, token, agent_key, scope="post:linkedin", mandate_id=inner["id"])

print(json.dumps({
    "receipt": receipt,
    "contentB64": base64.b64encode(content).decode(),
    "issuerDid": issuer_did(issuer_key),
    "mandateId": inner["id"],
}))
