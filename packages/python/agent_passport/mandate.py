"""Build the inner mandate (the object the human passkey signs)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

VC_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentpassport.dev/v1",
]
MANDATE_TYPE = ["VerifiableCredential", "AgentMandate"]
STATUS_TYPE = "AgentPassportStatus"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_inner_mandate(
    *,
    issuer_did: str,
    agent_id: str,
    agent_name: str,
    scope: list[str],
    human_id: str,
    ttl_seconds: int,
    status_base_url: str,
    mandate_id: str | None = None,
    status_list_index: int | None = None,
    valid_from: datetime | None = None,
) -> dict:
    """Assemble the inner mandate. Issuer fixes all fields BEFORE the human signs."""
    if not scope:
        raise ValueError("scope must be a non-empty list")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    mandate_id = mandate_id or f"urn:uuid:{uuid.uuid4()}"
    start = valid_from or _now()
    end = start + timedelta(seconds=ttl_seconds)
    base = status_base_url.rstrip("/")
    raw_id = mandate_id.split(":")[-1]

    inner: dict = {
        "@context": VC_CONTEXT,
        "type": MANDATE_TYPE,
        "id": mandate_id,
        "issuer": issuer_did,
        "validFrom": _rfc3339(start),
        "validUntil": _rfc3339(end),
        "credentialStatus": {
            "type": STATUS_TYPE,
            "id": f"{base}/status/{raw_id}",
            "statusListCredential": f"{base}/status-list",
        },
        "credentialSubject": {
            "id": agent_id,
            "agentName": agent_name,
            "scope": list(scope),
            "authorizedBy": {
                "humanId": human_id,
                "rootMethod": "webauthn",
            },
        },
    }
    if status_list_index is not None:
        inner["credentialStatus"]["statusListIndex"] = status_list_index
    return inner
