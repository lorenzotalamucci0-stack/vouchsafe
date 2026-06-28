# Integrating Vouchsafe — "ok, but how do I actually use it?"

Vouchsafe is not an app you log into. It is a **wrapper around what your agent already
produces**: the agent attaches a signed, revocable receipt to its output, and anyone verifies it.
This page shows how to put it into a real agent — Claude Code, Codex, an MCP tool, or a plain
script — in four moves.

## The mental model

```
  human ──issues once (passkey)──►  PASSPORT (token)  ──held by──►  your agent
                                          │                              │ produces output
                                          │ revoke anytime               ▼
                                          │                         sign_receipt(output, token, key)
                                          ▼                              │  {output, receipt}
   anyone ──verify_receipt()──►  ✅ authorized & live  /  ⛔ revoked ◄────┘
```

- **Agent identity** = an Ed25519 `did:key`. One keypair per agent. Its `did:key` *is* who it is.
- **Passport** = a mandate a human signs (with their passkey) authorizing *that* `did:key` for a
  *scope*, until an *expiry*, **revocable**. The agent holds it like an API token.
- **Receipt** = the agent signs the exact bytes of each output, bound to its passport.
- **Verify** = anyone checks signature + content-integrity + that the mandate is still live and the
  action in scope. Revoke the mandate → every receipt under it stops verifying, in real time.

No shared secret: verification needs only the issuer's **public** key. The verifier can't forge.

## The 4 moves (CLI)

```bash
# 0. install
cd packages/python && uv pip install -e .

# 1. agent identity (once)
vouchsafe keygen --out agent.pem        # prints the agent's did:key

# 2. a human issues a passport for that did:key (once) via the web issuer in server/,
#    signing with their passkey, then hands the agent the token:
export AP_AGENT_KEY=agent.pem
export AP_TOKEN=passport.jwt                  # path or raw JWT

# 3. agent signs whatever it emits
vouchsafe sign deliverable.md > deliverable.md.receipt

# 4. anyone gates on it (exit 0 = ok, 1 = reject; checks revocation over HTTP)
vouchsafe verify deliverable.md deliverable.md.receipt --issuer "$AP_ISSUER" || exit 1
```

## In code (Python SDK)

```python
from vouchsafe import sign_receipt, verify_receipt

# agent side — token + key come from issuance; scope/mandate_id are read from the token
receipt = sign_receipt(output_bytes, AP_TOKEN, agent_key, scope="post:linkedin", mandate_id=mid)

# verifier side — only the issuer's public key is needed
result = verify_receipt(output_bytes, receipt, expected_issuer=ISSUER_DID)
if not result.valid:
    reject(result.reason)        # "notRevoked", "outputHash", "scope", ...
```

Run the whole loop with no server and no passkey:

```bash
cd packages/python && uv run python ../../examples/standalone.py
```

## Integration patterns

| Where | How | Recipe |
|--|--|--|
| **Claude Code / Codex / any CLI agent** | `Stop`/`PostToolUse` hook runs `vouchsafe sign`; a downstream gate runs `vouchsafe verify` | [`integrations/claude-code/`](integrations/claude-code/) (+ runnable `demo_gate.py`) |
| **Agent → agent (A2A)** | the producing agent ships `{output, receipt}`; the consumer calls `verify_receipt` before trusting it | `examples/standalone.py` |
| **MCP tool** | the tool returns `{content, receipt}`; the client verifies before using the result | [`integrations/mcp/`](integrations/mcp/) (FastMCP server + runnable `demo.py`) |
| **Human-facing output** | publish the receipt next to the content; anyone pastes both into `/verify.html` | the web verifier in `server/` |

### Why a consumer would bother
Because revocation is the point: if a human revokes an agent's mandate (it went rogue, the task
ended, the contractor left), **already-produced output stops verifying instantly** — no redeploy,
no key rotation, no allowlist edit. The gate just starts returning `notRevoked`.

## Honest limits (don't oversell it to whoever you integrate with)
- The human signs an **opaque hash**, not the readable scope — informed consent depends on the
  issuer UI (see [`SPEC.md`](SPEC.md) §10).
- A receipt proves **authorized provenance**, not that the content is *true*, and does not survive
  the analog hole (re-typing/re-encoding changes the bytes).
- Revocation here is a simple online endpoint, **fail-closed** (issuer down ⇒ all reject). A cache/
  grace policy is yours to add (v2).
- `did:key` resolution and base58/multicodec are hand-rolled in v1 — fine for a reference impl,
  swap for an audited library before production.
