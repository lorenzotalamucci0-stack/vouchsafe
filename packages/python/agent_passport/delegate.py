"""Delegation chain (Pilastro 1.5): an agent re-delegates a NARROWER mandate to a sub-agent.

A child mandate is signed by the PARENT AGENT (not the human, not the service). It carries:
  - scope ⊆ parent scope, validUntil ≤ parent validUntil,
  - the parent mandate embedded as ``delegatedFrom`` (so the chain is self-contained),
  - the inherited human root (``authorizedBy``).

A child has NO human proof of its own — its human authorization is INHERITED through the chain.
``verify_chain`` validates every link up to the human-signed root; revoking (or expiring) any
ancestor invalidates the whole chain in real time.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .jwtvc import sign_vc_jwt, verify_vc_jws
from .keys import issuer_did
from .mandate import MANDATE_TYPE, STATUS_TYPE, VC_CONTEXT
from .status import StatusResolver
from .verify import _parse_ts, verify


@dataclass
class ChainResult:
    valid: bool
    reason: str | None = None
    depth: int = 0
    links: list = field(default_factory=list)  # leaf → root, each: {agent, agentName, scope, validUntil, kind}


def _unverified_vc(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})["vc"]


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _link(vc: dict, kind: str) -> dict:
    s = vc["credentialSubject"]
    return {"agent": s["id"], "agentName": s.get("agentName"), "scope": s.get("scope", []),
            "validUntil": vc["validUntil"], "kind": kind}


def sign_child_mandate(
    parent_token: str,
    *,
    child_agent_id: str,
    scope: list[str],
    ttl_seconds: int,
    parent_agent_key: Ed25519PrivateKey,
    status_base_url: str = "https://agentpassport.dev",
) -> str:
    """Sign a narrower child mandate. The parent agent (its key) attests the delegation."""
    parent_vc = _unverified_vc(parent_token)
    parent_subj = parent_vc["credentialSubject"]
    parent_agent_did = issuer_did(parent_agent_key)
    if parent_subj["id"] != parent_agent_did:
        raise ValueError("parent_agent_key does not match the parent mandate subject")
    if not scope:
        raise ValueError("scope must be non-empty")
    if not set(scope) <= set(parent_subj.get("scope", [])):
        raise ValueError("child scope must be a subset of the parent scope")

    now = datetime.now(timezone.utc)
    child_until = min(now + timedelta(seconds=ttl_seconds), _parse_ts(parent_vc["validUntil"]))
    if child_until <= now:
        raise ValueError("parent mandate already expired")

    mid = f"urn:uuid:{uuid.uuid4()}"
    base = status_base_url.rstrip("/")
    inner = {
        "@context": VC_CONTEXT,
        "type": MANDATE_TYPE,
        "id": mid,
        "issuer": parent_agent_did,
        "validFrom": _rfc3339(now),
        "validUntil": _rfc3339(child_until),
        "credentialStatus": {
            "type": STATUS_TYPE,
            "id": f"{base}/status/{mid.split(':')[-1]}",
            "statusListCredential": f"{base}/status-list",
        },
        "credentialSubject": {
            "id": child_agent_id,
            "agentName": f"{parent_subj.get('agentName', 'Agent')} › sub-agente",
            "scope": list(scope),
            "authorizedBy": parent_subj.get("authorizedBy", {}),
        },
        "delegationDepth": int(parent_vc.get("delegationDepth", 0)) + 1,
        "delegatedFrom": parent_token,
    }
    payload = {
        "iss": parent_agent_did, "jti": mid, "sub": child_agent_id,
        "nbf": int(now.timestamp()), "exp": int(child_until.timestamp()), "vc": inner,
    }
    return sign_vc_jwt(payload, {"typ": "mandate+jwt"}, parent_agent_key)


def verify_chain(
    token: str,
    *,
    required_scope: str | list[str] | None = None,
    expected_issuer: str | None = None,
    status_resolver: StatusResolver | None = None,
    check_revocation: bool = True,
    fail_closed: bool = True,
    now: datetime | None = None,
    max_depth: int = 6,
) -> ChainResult:
    """Verify a mandate that may be a delegation chain. A root mandate verifies as a 1-link chain."""
    now = now or datetime.now(timezone.utc)
    return _verify_node(token, required_scope, 0, now, max_depth,
                        expected_issuer, status_resolver, check_revocation, fail_closed)


def _verify_node(token, required_scope, depth, now, max_depth,
                 expected_issuer, status_resolver, check_revocation, fail_closed) -> ChainResult:
    vc = _unverified_vc(token)

    # --- Root mandate (human-signed, issued by the service) ---
    if "delegatedFrom" not in vc:
        res = verify(token, required_scope=required_scope, expected_issuer=expected_issuer,
                     status_resolver=status_resolver, check_revocation=check_revocation,
                     fail_closed=fail_closed, now=now)
        return ChainResult(res.valid, res.reason, depth, [_link(vc, "root")])

    # --- Delegated (child) mandate ---
    if depth >= max_depth:
        return ChainResult(False, "depthExceeded", depth, [_link(vc, "delegated")])

    ok, _payload, child_issuer = verify_vc_jws(token)
    if not ok:
        return ChainResult(False, "childSignature", depth, [_link(vc, "delegated")])

    parent_token = vc["delegatedFrom"]
    parent = _verify_node(parent_token, None, depth + 1, now, max_depth,
                          expected_issuer, status_resolver, check_revocation, fail_closed)
    leaf = _link(vc, "delegated")
    if not parent.valid:
        return ChainResult(False, parent.reason, depth, [leaf, *parent.links])

    parent_vc = _unverified_vc(parent_token)
    parent_subj = parent_vc["credentialSubject"]
    child_subj = vc["credentialSubject"]

    # Ordered checks for the child link.
    if not (child_issuer == parent_subj["id"] == vc.get("issuer")):
        reason = "childBinding"
    elif not set(child_subj.get("scope", [])) <= set(parent_subj.get("scope", [])):
        reason = "scopeNarrowing"
    elif _parse_ts(vc["validUntil"]) > _parse_ts(parent_vc["validUntil"]):
        reason = "expiryNarrowing"
    elif not (_parse_ts(vc["validFrom"]) <= now <= _parse_ts(vc["validUntil"])):
        reason = "notExpired"
    else:
        reason = None
        if check_revocation and "credentialStatus" in vc:
            try:
                status = status_resolver(vc["credentialStatus"]) if status_resolver else {"revoked": False}
                if bool(status.get("revoked", False)):
                    reason = "notRevoked"
            except Exception:
                reason = "notRevoked" if fail_closed else None
        if reason is None and required_scope is not None:
            req = [required_scope] if isinstance(required_scope, str) else list(required_scope)
            if not all(x in set(child_subj.get("scope", [])) for x in req):
                reason = "scope"

    return ChainResult(reason is None, reason, depth, [leaf, *parent.links])
