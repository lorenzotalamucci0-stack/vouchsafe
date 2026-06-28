"""Attach a Vouchsafe Content Receipt to any MCP tool result — and verify one.

The shared core used by both `server.py` (a real MCP server) and `demo.py` (a runnable
simulation). No MCP dependency here: it's just "wrap an output with a receipt" / "check it".
"""

from __future__ import annotations

import jwt

from vouchsafe import verify_receipt
from vouchsafe.receipt import sign_receipt


def signed_result(output: str, *, token: str, agent_key, scope: str, mandate_id: str) -> dict:
    """Return an MCP tool result that carries a signed receipt: {content, receipt}."""
    receipt = sign_receipt(output.encode("utf-8"), token, agent_key,
                           scope=scope, mandate_id=mandate_id)
    return {"content": output, "receipt": receipt}


def verify_result(result: dict, *, expected_issuer: str, status_resolver=None):
    """Client side: verify a {content, receipt} result. Returns the verification result."""
    return verify_receipt(
        result["content"].encode("utf-8"), result["receipt"],
        expected_issuer=expected_issuer, status_resolver=status_resolver,
    )


def mandate_fields(token: str) -> tuple[str, str, list[str]]:
    """Read (mandate_id, agent_did, scopes) from a passport token without verifying it."""
    vc = jwt.decode(token, options={"verify_signature": False})["vc"]
    return vc["id"], vc["credentialSubject"]["id"], vc["credentialSubject"].get("scope", [])
