"""Agent Passport demo server (FastAPI).

Flow:
  POST /register          register a passkey -> human root id
  POST /mandate/challenge build inner mandate -> challenge to sign with the passkey
  POST /mandate/issue     verify the assertion, sign the VC-JWT passport token
  GET  /status/{id}       revocation status (what a verifier fetches)
  POST /revoke            kill a mandate in real time
  POST /agent/act         protected agent endpoint — works ONLY with a live mandate
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agent_passport import (
    StatusStore,
    build_inner_mandate,
    extract_token,
    generate_issuer_key,
    human_id_from_public_key,
    issue,
    issuer_did,
    issuer_key_to_pem,
    load_issuer_key,
    revoke,
    sign_receipt,
    store_status_resolver,
    verify,
    verify_receipt,
)

HERE = Path(__file__).parent
STATIC = HERE / "static"
KEYS_DIR = HERE / ".keys"
DATA_DIR = HERE / ".data"
RP_ID = "localhost"
BASE_URL = os.environ.get("AP_BASE_URL", "http://localhost:8000")


def _load_or_create_key(name: str):
    KEYS_DIR.mkdir(exist_ok=True)
    pem_path = KEYS_DIR / name
    if pem_path.exists():
        return load_issuer_key(pem_path.read_bytes())
    key = generate_issuer_key()
    pem_path.write_bytes(issuer_key_to_pem(key))
    return key


ISSUER_KEY = _load_or_create_key("issuer_ed25519.pem")
ISSUER_DID = issuer_did(ISSUER_KEY)
# The agent holds a PERSISTENT key: its did:key is the mandate subject and signs receipts.
AGENT_KEY = _load_or_create_key("agent_ed25519.pem")
AGENT_DID = issuer_did(AGENT_KEY)
DATA_DIR.mkdir(exist_ok=True)
STORE = StatusStore(DATA_DIR / "status.json")
RESOLVER = store_status_resolver(STORE)

# In-memory demo state (resets on restart).
HUMANS: dict[str, dict] = {}      # humanId -> {credentialId, publicKey, alg}
PENDING: dict[str, dict] = {}     # mandateId -> {inner, humanId}

# An issuer enforces its own policy on what scopes it will grant. The demo uses a fixed
# allowlist; a real issuer would resolve this per human/agent/organization.
ALLOWED_SCOPES = {"read:calendar", "book:flights", "post:linkedin", "send:email"}
MAX_TTL_SECONDS = 24 * 3600

app = FastAPI(title="Agent Passport demo")


# ---------- models ----------
class RegisterBody(BaseModel):
    credentialId: str
    publicKey: str   # base64url SPKI DER
    alg: int = -7


class ChallengeBody(BaseModel):
    humanId: str
    agentName: str
    scope: list[str]
    ttlSeconds: int = 300


class Assertion(BaseModel):
    credentialId: str
    authenticatorData: str
    clientDataJSON: str
    signature: str


class IssueBody(BaseModel):
    mandateId: str
    assertion: Assertion


class RevokeBody(BaseModel):
    mandateId: str


class ActBody(BaseModel):
    action: str = Field(max_length=128)


class VerifyReceiptBody(BaseModel):
    # Bounded to keep the public verify endpoint from hashing/parsing unbounded input (DoS).
    content: str = Field(max_length=65536)
    receipt: str = Field(max_length=16384)


# ---------- routes ----------
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/issuer", include_in_schema=False)
def issuer_info():
    return {"issuer": ISSUER_DID, "rpId": RP_ID}


@app.post("/register")
def register(body: RegisterBody):
    human_id = human_id_from_public_key(body.publicKey)
    HUMANS[human_id] = {
        "credentialId": body.credentialId,
        "publicKey": body.publicKey,
        "alg": body.alg,
    }
    return {"humanId": human_id}


@app.post("/mandate/challenge")
def mandate_challenge(body: ChallengeBody):
    if body.humanId not in HUMANS:
        return JSONResponse({"error": "unknown human; register a passkey first"}, status_code=400)
    # Issuer policy: only grant scopes the issuer recognizes, and bound the lifetime.
    unknown = [s for s in body.scope if s not in ALLOWED_SCOPES]
    if not body.scope or unknown:
        return JSONResponse({"error": f"unsupported scope(s): {unknown or 'empty'}"}, status_code=400)
    if not (0 < body.ttlSeconds <= MAX_TTL_SECONDS):
        return JSONResponse({"error": f"ttlSeconds must be in 1..{MAX_TTL_SECONDS}"}, status_code=400)
    inner = build_inner_mandate(
        issuer_did=ISSUER_DID,
        agent_id=AGENT_DID,          # the persistent agent identity (signs receipts)
        agent_name=body.agentName,
        scope=body.scope,
        human_id=body.humanId,
        ttl_seconds=body.ttlSeconds,
        status_base_url=BASE_URL,
    )
    from agent_passport.jcs import b64url, mandate_hash

    PENDING[inner["id"]] = {"inner": inner, "humanId": body.humanId}
    return {
        "mandateId": inner["id"],
        "challenge": b64url(mandate_hash(inner)),
        "credentialId": HUMANS[body.humanId]["credentialId"],
        "validUntil": inner["validUntil"],
    }


@app.post("/mandate/issue")
def mandate_issue(body: IssueBody):
    pending = PENDING.get(body.mandateId)
    if pending is None:
        return JSONResponse({"error": "unknown or expired mandate challenge"}, status_code=400)
    human = HUMANS[pending["humanId"]]
    # The assertion must come from the passkey this human registered.
    if body.assertion.credentialId != human["credentialId"]:
        return JSONResponse({"error": "credentialId does not match the registered passkey"}, status_code=400)
    human_proof = {
        "type": "WebAuthnAssertion2026",
        "credentialId": body.assertion.credentialId,
        "authenticatorData": body.assertion.authenticatorData,
        "clientDataJSON": body.assertion.clientDataJSON,
        "signature": body.assertion.signature,
        "publicKey": human["publicKey"],
        "alg": human["alg"],
    }
    try:
        token = issue(pending["inner"], human_proof, ISSUER_KEY)
    except Exception as exc:
        return JSONResponse({"error": f"could not issue: {exc}"}, status_code=400)

    STORE.register(body.mandateId)
    PENDING.pop(body.mandateId, None)
    return {"token": token, "mandate": {**pending["inner"], "humanProof": human_proof}}


@app.get("/status/{raw_id}")
def status(raw_id: str):
    rec = STORE.get(raw_id)
    if rec is None:
        return JSONResponse(
            {"mandateId": raw_id, "revoked": True, "revokedAt": None, "reason": "unknown"},
            status_code=404,
        )
    return rec


@app.post("/revoke")
def revoke_mandate(body: RevokeBody):
    # DEMO ONLY: unauthenticated so the "revoke" button just works. A production issuer
    # MUST authenticate this — only the human who authorized the mandate (or the issuer
    # admin) may revoke it — and should audit-log every revocation. See SPEC.md §Threat model.
    ok = revoke(body.mandateId, STORE)
    if not ok:
        return JSONResponse({"error": "unknown mandate"}, status_code=404)
    return {"revoked": True, "mandateId": body.mandateId}


@app.post("/agent/act")
async def agent_act(body: ActBody, request: Request):
    """The protected endpoint. Honors the action ONLY with a live, in-scope mandate."""
    token = extract_token(request.headers.get("Authorization"))
    if not token:
        return JSONResponse({"ok": False, "reason": "noMandate"}, status_code=401)

    result = verify(
        token,
        required_scope=body.action,
        expected_issuer=ISSUER_DID,
        status_resolver=RESOLVER,
    )
    payload = {
        "ok": result.valid,
        "reason": result.reason,
        "checks": result.checks,
        "degraded": result.degraded,
    }
    if not result.valid:
        return JSONResponse(payload, status_code=403)

    # Authorized → produce content and attach a signed Content Receipt (Pilastro 2).
    agent_name = result.mandate["credentialSubject"]["agentName"]
    content = _draft_content(body.action, agent_name)
    mandate_id = result.mandate["id"]
    receipt = sign_receipt(
        content.encode("utf-8"), token, AGENT_KEY, scope=body.action, mandate_id=mandate_id
    )
    payload["message"] = f"✓ Agent performed '{body.action}' on behalf of its human."
    payload["content"] = content
    payload["receipt"] = receipt
    return payload


def _draft_content(action: str, agent_name: str) -> str:
    """The agent's deliverable for an action (the bytes the receipt is signed over)."""
    drafts = {
        "post:linkedin": (
            "Just shipped Agent Passport — verifiable, revocable mandates for AI agents. "
            "Every action an agent takes can now carry a signed receipt proving a real human "
            "authorized it, within scope, revocable in real time. The trust layer for the agent web."
        ),
        "send:email": (
            "Subject: Booking confirmed\n\nHi — your flight is booked. This message was produced "
            "by an authorized agent acting under a verifiable human mandate."
        ),
        "book:flights": "Flight booking request: MXP→JFK, 2026-07-15, 1 passenger, economy.",
        "read:calendar": "Calendar digest: 3 meetings today; next free slot 15:00–16:00.",
    }
    body = drafts.get(action, f"Output for action '{action}'.")
    return f"{body}\n\n— produced by {agent_name}"


@app.post("/verify-receipt")
def verify_receipt_endpoint(body: VerifyReceiptBody):
    """Consumer-side: paste content + receipt, get a plain-language verdict."""
    result = verify_receipt(
        body.content.encode("utf-8"),
        body.receipt,
        expected_issuer=ISSUER_DID,
        status_resolver=RESOLVER,
    )
    rc = result.receipt or {}
    subject = rc.get("credentialSubject", {})
    human_id = None
    if result.mandate and result.mandate.mandate:
        human_id = result.mandate.mandate["credentialSubject"]["authorizedBy"]["humanId"]
    summary = _receipt_summary(result, subject, human_id)
    return {
        "valid": result.valid,
        "reason": result.reason,
        "checks": result.checks,
        "degraded": result.degraded,
        "summary": summary,
        "agentId": subject.get("agentId"),
        "humanId": human_id,
        "scope": subject.get("scope"),
        "producedAt": subject.get("producedAt"),
    }


def _receipt_summary(result, subject: dict, human_id: str | None) -> str:
    agent = subject.get("agentId", "?")
    scope = subject.get("scope", "?")
    human = (human_id or "?")[:48]
    if result.valid:
        return (f"VALIDO — prodotto dall'agente {agent[:24]}…, sotto mandato umano {human}…, "
                f"scope '{scope}'. Firma, contenuto, mandato e revoca: tutti verificati.")
    reasons = {
        "receiptSignature": "la firma della ricevuta non è valida (contenuto/ricevuta manomessi).",
        "outputHash": "il contenuto NON corrisponde alla ricevuta (è stato modificato).",
        "agentBinding": "l'agente della ricevuta non combacia con il mandato.",
        "notRevoked": "il mandato è stato REVOCATO — la ricevuta non è più valida.",
        "notExpired": "il mandato era scaduto al momento della verifica.",
        "scope": "l'azione è fuori dallo scope autorizzato dal mandato.",
        "issuerSignature": "la firma dell'issuer del mandato non è valida.",
        "humanProof": "la prova umana (passkey) del mandato non è valida.",
        "trustedIssuer": "il mandato non proviene dall'issuer atteso.",
    }
    return f"NON VALIDO — {reasons.get(result.reason, result.reason)}"


app.mount("/", StaticFiles(directory=STATIC), name="static")
