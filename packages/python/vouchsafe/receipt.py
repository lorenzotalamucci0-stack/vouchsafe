"""Content Receipt (Pilastro 2): a signed receipt binding an agent's output to its mandate.

A receipt answers: *which agent produced these exact bytes, under which human mandate,
within which scope, at what time — and was it authorized?* It is a VC-JWT signed by the
AGENT (Ed25519 did:key); the agent DID must equal the mandate's credentialSubject.id, and
the mandate (embedded) is verified live with Pilastro 1's ``verify`` — so revoking the
mandate invalidates the receipt in real time.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import InvalidTokenError
from .jwtvc import sign_vc_jwt, verify_vc_jws
from .keys import issuer_did
from .mandate import VC_CONTEXT
from .status import StatusResolver
from .verify import VerificationResult, verify

RECEIPT_TYPE = ["VerifiableCredential", "ContentReceipt"]


@dataclass
class ReceiptVerificationResult:
    valid: bool
    checks: dict = field(default_factory=dict)
    reason: str | None = None
    degraded: bool = False
    receipt: dict | None = None
    mandate: VerificationResult | None = None


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def output_hash(output_bytes: bytes) -> str:
    """Hex SHA-256 of the exact output bytes (the hard hash; perceptual hash is future work)."""
    return hashlib.sha256(output_bytes).hexdigest()


def sign_receipt(
    output_bytes: bytes,
    mandate_token: str,
    agent_key: Ed25519PrivateKey,
    *,
    scope: str,
    mandate_id: str,
) -> str:
    """Sign a Content Receipt over ``output_bytes`` for the given mandate.

    ``scope`` is the action the output is produced for (checked against the mandate scope
    at verify time). ``mandate_id`` is the mandate's id (``jti``/``credentialSubject`` ref).
    The agent key's did:key becomes the receipt issuer and MUST match the mandate subject.
    """
    agent_did = issuer_did(agent_key)
    now = _now_rfc3339()
    receipt_id = f"urn:uuid:{uuid.uuid4()}"
    credential = {
        "@context": VC_CONTEXT,
        "type": RECEIPT_TYPE,
        "id": receipt_id,
        "issuer": agent_did,
        "validFrom": now,
        "credentialSubject": {
            "agentId": agent_did,
            "mandateId": mandate_id,
            "scope": scope,
            "output": {
                "hashAlg": "sha-256",
                "hash": output_hash(output_bytes),
                "bytes": len(output_bytes),
            },
            "producedAt": now,
        },
        "mandate": mandate_token,
    }
    payload = {"iss": agent_did, "jti": receipt_id, "sub": agent_did, "vc": credential}
    return sign_vc_jwt(payload, {"typ": "receipt+jwt"}, agent_key)


def verify_receipt(
    output_bytes: bytes,
    receipt_token: str,
    *,
    status_resolver: StatusResolver | None = None,
    expected_issuer: str | None = None,
    check_revocation: bool = True,
    fail_closed: bool = True,
    now: datetime | None = None,
) -> ReceiptVerificationResult:
    """Verify a Content Receipt against the exact output bytes.

    Checks, in order: ``receiptSignature`` (agent did:key) → ``outputHash`` (bytes match) →
    ``agentBinding`` (receipt agent == mandate subject & mandateId matches) → the embedded
    mandate via Pilastro 1 ``verify`` (issuer sig, human proof, expiry, **revocation**, scope).
    ``valid`` is the AND of all checks; ``reason`` is the first failure.
    """
    checks: dict = {}

    def finalize(**kwargs) -> ReceiptVerificationResult:
        reason = next((n for n, ok in checks.items() if not ok), None)
        return ReceiptVerificationResult(valid=reason is None, checks=checks, reason=reason, **kwargs)

    # 1. Receipt signature (agent did:key).
    ok, payload, agent_did = verify_vc_jws(receipt_token)
    checks["receiptSignature"] = ok
    if not ok:
        return finalize()

    credential = payload.get("vc")
    if not isinstance(credential, dict) or credential.get("type") != RECEIPT_TYPE:
        raise InvalidTokenError("not a ContentReceipt")
    subject = credential.get("credentialSubject", {})
    out = subject.get("output", {})
    mandate_token = credential.get("mandate")
    if not isinstance(mandate_token, str):
        raise InvalidTokenError("receipt has no embedded mandate")

    # 1b. Internal claim consistency: the signed JWS claims and the VC must agree, so a valid
    #     agent cannot ship misleading internal fields.
    checks["receiptClaims"] = (
        credential.get("issuer") == agent_did
        and payload.get("sub") == agent_did
        and payload.get("jti") == credential.get("id")
    )
    if not checks["receiptClaims"]:
        return finalize(receipt=credential)

    # 2. Output hash matches the exact bytes.
    checks["outputHash"] = (out.get("hashAlg") == "sha-256") and (out.get("hash") == output_hash(output_bytes))
    if not checks["outputHash"]:
        return finalize(receipt=credential)

    # 3. Agent binding: receipt issuer == receipt.agentId, and that == mandate subject id.
    mandate_result = verify(
        mandate_token,
        required_scope=subject.get("scope"),
        expected_issuer=expected_issuer,
        status_resolver=status_resolver,
        check_revocation=check_revocation,
        fail_closed=fail_closed,
        now=now,
    )
    mandate_subject_id = None
    if mandate_result.mandate:
        mandate_subject_id = mandate_result.mandate.get("credentialSubject", {}).get("id")
        mandate_id = mandate_result.mandate.get("id")
    else:
        mandate_id = None
    checks["agentBinding"] = (
        agent_did == subject.get("agentId")
        and agent_did == mandate_subject_id
        and subject.get("mandateId") == mandate_id
    )
    if not checks["agentBinding"]:
        return finalize(receipt=credential, mandate=mandate_result)

    # 4. Mandate validity — merge its check breakdown (issuerSignature, humanProof, notExpired,
    #    notRevoked, scope, ...) so the verdict shows the full chain. Revocation is live.
    checks.update(mandate_result.checks)
    return finalize(degraded=mandate_result.degraded, receipt=credential, mandate=mandate_result)
