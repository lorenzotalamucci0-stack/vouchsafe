"""Mint a delegation chain (Python SDK) and print it as JSON, for the JS interop test."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from vouchsafe import (  # noqa: E402
    build_inner_mandate, generate_issuer_key, human_id_from_public_key,
    issue, issuer_did, sign_child_mandate,
)
from _passkey import SoftwarePasskey  # noqa: E402

issuer_key = generate_issuer_key()
agent_key = generate_issuer_key()
passkey = SoftwarePasskey()
inner = build_inner_mandate(
    issuer_did=issuer_did(issuer_key), agent_id=issuer_did(agent_key), agent_name="Acme Bot",
    scope=["read:calendar", "book:flights", "post:linkedin"],
    human_id=human_id_from_public_key(passkey.spki_b64url), ttl_seconds=600,
    status_base_url="http://localhost:8090",
)
root = issue(inner, passkey.sign_mandate(inner), issuer_key)
child = sign_child_mandate(root, child_agent_id=issuer_did(generate_issuer_key()),
                           scope=["book:flights"], ttl_seconds=300, parent_agent_key=agent_key,
                           status_base_url="http://localhost:8090")

print(json.dumps({"child": child, "rootId": inner["id"], "expectedIssuer": issuer_did(issuer_key)}))
