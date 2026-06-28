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
from pydantic import BaseModel

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
    store_status_resolver,
    verify,
)

HERE = Path(__file__).parent
STATIC = HERE / "static"
KEYS_DIR = HERE / ".keys"
DATA_DIR = HERE / ".data"
RP_ID = "localhost"
BASE_URL = os.environ.get("AP_BASE_URL", "http://localhost:8000")


def _load_or_create_issuer():
    KEYS_DIR.mkdir(exist_ok=True)
    pem_path = KEYS_DIR / "issuer_ed25519.pem"
    if pem_path.exists():
        return load_issuer_key(pem_path.read_bytes())
    key = generate_issuer_key()
    pem_path.write_bytes(issuer_key_to_pem(key))
    return key


ISSUER_KEY = _load_or_create_issuer()
ISSUER_DID = issuer_did(ISSUER_KEY)
DATA_DIR.mkdir(exist_ok=True)
STORE = StatusStore(DATA_DIR / "status.json")
RESOLVER = store_status_resolver(STORE)

# In-memory demo state (resets on restart).
HUMANS: dict[str, dict] = {}      # humanId -> {credentialId, publicKey, alg}
PENDING: dict[str, dict] = {}     # mandateId -> {inner, humanId}

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
    action: str


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
    # Mint a fresh did:key identity for the agent.
    agent_id = issuer_did(generate_issuer_key())
    inner = build_inner_mandate(
        issuer_did=ISSUER_DID,
        agent_id=agent_id,
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
    if result.valid:
        payload["message"] = f"✓ Agent performed '{body.action}' on behalf of its human."
        return payload
    return JSONResponse(payload, status_code=403)


app.mount("/", StaticFiles(directory=STATIC), name="static")
