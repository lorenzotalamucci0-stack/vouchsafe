# Quickstart — add Agent Passport to your agent in 5 minutes

Three integration points. Pick the one you are: **verifier** (you receive agent actions),
**agent** (you carry a mandate), or **issuer** (you mint mandates for humans).

> Everything runs locally. Start the demo server first:
> ```bash
> cd packages/python && uv venv && uv pip install -e ".[server]"
> cd ../../server && ../packages/python/.venv/bin/python run.py
> # run.py picks port 8000 (or the next free one) and prints the URL to open.
> ```

---

## 1. You are a VERIFIER (most common)

You run a tool/API and want to honor an action **only** if a real human authorized this agent,
the mandate hasn't expired, hasn't been revoked, and covers the action.

### Python

```python
from agent_passport import verify, extract_token

def handle_request(headers, action):
    token = extract_token(headers.get("Authorization"))   # "Mandate <jwt>"
    result = verify(
        token,
        required_scope=action,                  # e.g. "post:linkedin"
        expected_issuer="did:key:z6Mk...",      # pin the issuer you trust
    )
    if not result.valid:
        return 403, {"denied": result.reason}   # "notRevoked", "scope", "notExpired", ...
    return 200, {"ok": True, "checks": result.checks}
```

### JavaScript (Node 20+ / browser)

```js
import { verify, extractToken } from "agent-passport";

const token = extractToken(req.headers.authorization);
const result = await verify(token, {
  requiredScope: "post:linkedin",
  expectedIssuer: "did:key:z6Mk...",
});
if (!result.valid) return res.status(403).json({ denied: result.reason });
```

`verify` checks, in order: **issuer signature → trusted issuer → human proof (WebAuthn) →
not expired → not revoked → scope**. Revocation is the only online step; everything else is
offline. On a status-endpoint error it fails **closed** by default (`failClosed: true`).

---

## 2. You are an AGENT

Carry the token and present it on every action:

```python
from agent_passport import present
headers = present(my_token)        # {"Authorization": "Mandate <jwt>"}
requests.post("https://tool/api", headers=headers, json={"action": "post:linkedin"})
```

```js
import { present } from "agent-passport";
fetch(url, { headers: present(myToken), method: "POST", body });
```

---

## 3. You are an ISSUER

Issuing is a 2-call ceremony because the **human signs the mandate with their passkey** (the
issuer fixes the fields *before* the human signs). See `server/app.py` for the full flow; the
core is:

```python
from agent_passport import build_inner_mandate, issue, issuer_did
from agent_passport.jcs import b64url, mandate_hash

# 1. Build the inner mandate and hand its hash to the browser as the WebAuthn challenge.
inner = build_inner_mandate(
    issuer_did=issuer_did(issuer_key),
    agent_id="did:key:zAgent...",
    agent_name="Acme Bot",
    scope=["read:calendar", "book:flights"],
    human_id=human_id,                 # from the registered passkey
    ttl_seconds=300,
    status_base_url="https://issuer.example",
)
challenge = b64url(mandate_hash(inner))   # -> navigator.credentials.get({challenge})

# 2. After the browser returns the WebAuthn assertion, wrap + sign the VC-JWT.
token = issue(inner, human_proof, issuer_key)   # verifies the human proof, then signs
```

Browser side (native WebAuthn, zero deps) — see `server/static/app.js` for the copy-paste
version of `navigator.credentials.create` (register) and `.get` (sign the challenge).

### Revocation

```python
from agent_passport import revoke, StatusStore
revoke(mandate_id, StatusStore("status.json"))   # the agent is rejected on its next action
```

---

## 4. Attach a RECEIPT to your agent's output (Pilastro 2) — 5 minutes

A **Content Receipt** binds *these exact output bytes* to the agent's mandate. Revoking the
mandate invalidates the receipt in real time.

### Agent side — sign the receipt over the output

```python
from agent_passport import sign_receipt
output = b"...the exact bytes your agent produced..."
receipt = sign_receipt(
    output, mandate_token, agent_key,   # agent_key's did:key MUST be the mandate subject
    scope="post:linkedin",              # the action this output is for
    mandate_id=mandate_id,
)
# ship `output` + `receipt` together
```

```js
import { signReceipt } from "agent-passport";
const receipt = await signReceipt(outputBytes, mandateToken,
  { privateKey: agentKey, agentDid, scope: "post:linkedin", mandateId });
```

### Consumer side — verify a receipt against the bytes

```python
from agent_passport import verify_receipt
r = verify_receipt(output, receipt, expected_issuer="did:key:z6Mk...")
# r.valid, r.reason ("outputHash" | "notRevoked" | "scope" | "agentBinding" | ...), r.checks
```

```js
import { verifyReceipt } from "agent-passport";
const r = await verifyReceipt(outputBytes, receipt, { expectedIssuer: "did:key:z6Mk..." });
```

A drop-in widget (`server/static/verify.html` → `/verify-receipt`) gives anyone a plain-language
verdict: *"VALID — produced by agent X, under human mandate Y, scope Z"* / *"✗ mandate REVOKED"*.

---

## What "done" looks like

- Format spec → [`SPEC.md`](SPEC.md) (mandate + Content Receipt §13 + Threat model)
- Python SDK → [`packages/python`](packages/python) · `uv run pytest`
- JS SDK → [`packages/js`](packages/js) · `node --test` (verifies a Python-issued token + receipt)
- Live demo → [`server`](server) · passkey, real-time revoke, content receipt + `/verify.html`
- E2E proof → [`e2e`](e2e) · `node run.mjs` (mandate) · `node receipt.mjs` (content receipt)
