# CLAUDE.md — Vouchsafe

Guidance for Claude Code (and contributors) working in this repository.

## What this is

**Vouchsafe** — a verifiable, revocable receipt for AI content. A human authorizes an agent by
signing a mandate with their passkey (WebAuthn); every output the agent produces carries a signed
**Content Receipt**; revoking the mandate invalidates the receipt in real time. The differentiator
vs adjacent work (Signet, Microsoft APS, AP2, C2PA): revocation that kills the receipt **on
content**, live. See `README.md` for positioning and `CONCEPT.md` for the full design.

## Layout

- `packages/python/vouchsafe/` — the Python SDK (issue, verify, sign_receipt, verify_receipt,
  delegation chain, status/revocation, WebAuthn proof) + the `vouchsafe` CLI.
- `packages/js/` — a JavaScript SDK that cross-verifies tokens minted by Python.
- `server/` — a FastAPI demo: passkey registration, mandate issuance, live revoke, the consumer
  verifier at `/verify.html`, and the in-page developer docs.
- `e2e/` — Playwright end-to-end tests driving a WebAuthn virtual authenticator.
- `integrations/` — recipes (Claude Code hook, MCP) + runnable demos.
- `examples/` — `standalone.py`: the whole loop in ~40 lines, no server.
- `SPEC.md` — the wire format (mandate, Content Receipt §13, threat model).
- `INTEGRATION.md` — how to put it into a real agent.

## Working in this repo

- **Verify with real execution**, never assume. Gates: `cd packages/python && pytest`;
  `cd packages/js && node --test`; `cd e2e && node run.mjs|receipt.mjs|chain.mjs|uicheck.mjs`
  (E2E and uicheck need the demo server running — `cd server && python run.py`).
- **Security**: keys/credentials never hardcoded; the issuer key lives in `server/.keys/`
  (gitignored). Identity for writes comes from the signature/session, never from a request body.
- The credential context URL is `https://vouchsafe.dev/v1`; verifiers MUST reject unknown
  context/type (SPEC §12) — enforced in `verify()` and in the delegation chain.
- `devkit.py` mints mandates without a real human — **dev/tests/examples only** (it hard-refuses
  to import under `AP_ENV=production`).

## Honest limits (keep them stated, don't oversell)

The passkey signs an opaque hash (not the readable scope); a receipt proves authorized provenance,
not truth, and does not survive the analog hole; revocation v1 is a simple fail-closed endpoint;
Art.50 is complemented, not satisfied, by this. All documented in `SPEC.md` §10–11 and `README.md`.
