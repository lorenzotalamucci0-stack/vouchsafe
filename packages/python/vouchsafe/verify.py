"""Verify a passport token. The heart of the SDK.

Checks, in order: issuer signature → (trusted issuer) → human proof → not expired →
not revoked → scope. Returns a structured result; ``valid`` is the AND of all performed
checks and ``reason`` names the first failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import jwt
from cryptography.exceptions import InvalidSignature

from .errors import InvalidTokenError
from .keys import did_to_public_key
from .status import StatusResolver, http_status_resolver
from .webauthn_proof import verify_human_proof


@dataclass
class VerificationResult:
    valid: bool
    checks: dict = field(default_factory=dict)
    degraded: bool = False
    mandate: dict | None = None
    reason: str | None = None


def _parse_ts(rfc3339: str) -> datetime:
    # Accept the full RFC 3339 surface (fractional seconds, numeric offsets), not only "...Z".
    # We issue the strict "...Z" form, but verifiers MUST read what other issuers legitimately emit.
    dt = datetime.fromisoformat(rfc3339)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _finalize(checks: dict, **kwargs) -> VerificationResult:
    reason = next((name for name, ok in checks.items() if not ok), None)
    return VerificationResult(valid=reason is None, checks=checks, reason=reason, **kwargs)


def verify(
    token: str,
    *,
    required_scope: str | list[str] | None = None,
    expected_issuer: str | None = None,
    status_resolver: StatusResolver | None = None,
    check_revocation: bool = True,
    fail_closed: bool = True,
    now: datetime | None = None,
) -> VerificationResult:
    now = now or datetime.now(timezone.utc)
    checks: dict = {}

    # --- Read the issuer DID (unverified) to obtain its public key ---
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        issuer_did_str = unverified["iss"]
        pub = did_to_public_key(issuer_did_str)
    except Exception as exc:  # malformed token
        raise InvalidTokenError(f"cannot read token: {exc}") from exc

    # --- 1. Issuer signature ---
    try:
        payload = jwt.decode(
            token,
            pub,
            algorithms=["EdDSA"],
            options={"verify_exp": False, "verify_nbf": False, "verify_aud": False},
        )
        header = jwt.get_unverified_header(token)
        # kid, when present, must name the same issuer DID whose key we verified with.
        kid_ok = header.get("kid") in (None, issuer_did_str)
        checks["issuerSignature"] = kid_ok
        if not kid_ok:
            return _finalize({"issuerSignature": False})
    except (jwt.InvalidSignatureError, InvalidSignature):
        return _finalize({"issuerSignature": False})
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(f"invalid token: {exc}") from exc

    credential = payload.get("vc")
    if not isinstance(credential, dict) or "humanProof" not in credential:
        raise InvalidTokenError("token has no embedded credential / humanProof")

    # --- 1b. Recognized format (SPEC §12): reject contexts/types we don't understand ---
    ctx = credential.get("@context") or []
    typ = credential.get("type") or []
    checks["recognizedFormat"] = ("https://vouchsafe.dev/v1" in ctx) and ("AgentMandate" in typ)
    if not checks["recognizedFormat"]:
        return _finalize(checks, mandate=credential)

    # --- 2. Trusted issuer (only if the verifier pinned one) ---
    if expected_issuer is not None:
        checks["trustedIssuer"] = issuer_did_str == expected_issuer
        if not checks["trustedIssuer"]:
            return _finalize(checks, mandate=credential)

    human_proof = credential["humanProof"]
    inner = {k: v for k, v in credential.items() if k != "humanProof"}

    # --- 3. Human proof (WebAuthn assertion over the mandate hash) ---
    proof = verify_human_proof(inner, human_proof)
    checks["humanProof"] = proof.ok
    if not proof.ok:
        return _finalize(checks, mandate=credential)

    # --- 4. Not expired ---
    try:
        valid_from = _parse_ts(inner["validFrom"])
        valid_until = _parse_ts(inner["validUntil"])
    except (KeyError, ValueError) as exc:
        raise InvalidTokenError(f"invalid validity window: {exc}") from exc
    checks["notExpired"] = valid_from <= now <= valid_until
    if not checks["notExpired"]:
        return _finalize(checks, mandate=credential)

    # --- 5. Not revoked (online) ---
    degraded = False
    if check_revocation:
        resolver = status_resolver or http_status_resolver
        try:
            status = resolver(inner["credentialStatus"])
            checks["notRevoked"] = not bool(status.get("revoked", False))
        except Exception:
            degraded = True
            checks["notRevoked"] = not fail_closed
        if not checks["notRevoked"]:
            return _finalize(checks, degraded=degraded, mandate=credential)

    # --- 6. Scope ---
    if required_scope is not None:
        required = [required_scope] if isinstance(required_scope, str) else list(required_scope)
        granted = set(inner["credentialSubject"].get("scope", []))
        checks["scope"] = all(item in granted for item in required)

    return _finalize(checks, degraded=degraded, mandate=credential)
