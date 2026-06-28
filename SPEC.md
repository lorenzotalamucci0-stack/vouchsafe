# Agent Passport — Mandate Specification v1

> **Status:** Draft v1 (2026-06-28). A thin, verifiable, revocable mandate format proving that an
> AI agent acts on behalf of an authorized real human, within a scope, until an expiry.
>
> Aligned with [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
> (field model) and secured as a [VC-JOSE / JWT](https://www.w3.org/TR/vc-jose-cose/). Data model
> inspired by *AIP — Agent Identity Protocol* (arXiv 2603.24775).

## 0. What this is (and is not)

- **Is:** a delegated, time-boxed, scope-limited, revocable **capability** carried by an agent and
  verifiable by anyone — proving a *human mandate*, not a *human identity*.
- **Is not:** proof-of-personhood, a biometric, a new root-of-trust, or a blockchain token. The
  human root of trust is **inherited** from existing methods (WebAuthn/passkey in v1; World ID or a
  third-party VC are pluggable later).

## 1. Roles

| Role | Description |
|------|-------------|
| **Human** | A real person who authenticates with a passkey (WebAuthn). The *root*. |
| **Issuer** | The service that assembles and signs the mandate (Ed25519 `did:key`). May be self-hosted. |
| **Agent** | The AI that *carries* the mandate (a `passport token`) and presents it when acting. |
| **Verifier** | Anyone receiving an agent action; checks the mandate before honoring it. |

## 2. The two-signature model (core)

A valid mandate carries **two** independent cryptographic proofs:

1. **Human proof** — a WebAuthn assertion from the human's passkey, where the
   `challenge = SHA-256(canonical inner mandate)`. This binds *this exact mandate* to a real
   human-controlled authenticator. (Pattern: WebAuthn-for-signing.)
2. **Issuer proof** — the whole credential serialized as a **VC-JWT** signed with the issuer's
   Ed25519 key (`EdDSA`). This proves issuance and binds the mandate to its revocation authority.

Proofs 1–2, expiry (§5) and scope (§6) are checkable **offline**. Revocation (§7) is **online**.

## 3. Canonical form & hashing

The **inner mandate** is the JSON object of §4 *without* the `humanProof` member.

- **Canonicalization:** [RFC 8785 JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
  — lexicographically sorted keys, no insignificant whitespace, UTF-8.
- **Hash:** `challenge = SHA-256(JCS(inner_mandate))`, 32 bytes.
- The WebAuthn `clientDataJSON.challenge` MUST equal `base64url(challenge)` (no padding).

Canonicalization makes the human proof reproducible by any verifier from the credential alone.

## 4. Mandate fields (inner mandate)

```jsonc
{
  "@context": ["https://www.w3.org/ns/credentials/v2",
               "https://agentpassport.dev/v1"],
  "type": ["VerifiableCredential", "AgentMandate"],
  "id": "urn:uuid:5f3b...",                       // unique mandate id
  "issuer": "did:key:z6MkhaXgBZD...",             // Ed25519 issuer DID
  "validFrom":  "2026-06-28T10:00:00Z",           // RFC 3339 UTC
  "validUntil": "2026-06-28T10:05:00Z",           // hard expiry
  "credentialStatus": {
    "type": "AgentPassportStatus",                // v1; → "BitstringStatusListEntry" in v2
    "id": "https://issuer.example/status/5f3b...",// GET → {revoked: bool}
    "statusListIndex": 42,                         // reserved for Bitstring Status List v2
    "statusListCredential": "https://issuer.example/status-list"
  },
  "credentialSubject": {
    "id": "did:key:z6Mk...",                       // the AGENT identifier
    "agentName": "Acme Booking Bot",               // human-readable label
    "scope": ["read:calendar", "book:flights"],    // capability scope (see §6)
    "authorizedBy": {
      "humanId": "did:key:z6Mk...",                // PSEUDONYMOUS human root (from passkey pubkey)
      "rootMethod": "webauthn"                      // root-of-trust method
    }
  }
}
```

### Field rules
- `id` — globally unique; `urn:uuid:` RECOMMENDED.
- `issuer` — MUST be a `did:key` resolvable to an Ed25519 public key (offline).
- `validFrom` / `validUntil` — RFC 3339, UTC `Z`. `validUntil` MUST be present (no perpetual mandates).
- `credentialStatus.id` — an HTTPS (or `http://localhost` in dev) URL returning the status object (§7).
- `credentialSubject.scope` — non-empty array of scope strings (§6).
- `authorizedBy.humanId` — a `did:key` derived from the human's passkey public key. Pseudonymous:
  it does not reveal who the human is, only that *a* consistent human root authorized it.

## 5. Human proof object

Appended to the inner mandate to form the **full credential**:

```jsonc
"humanProof": {
  "type": "WebAuthnAssertion2026",
  "credentialId": "base64url",         // WebAuthn credential id
  "authenticatorData": "base64url",
  "clientDataJSON": "base64url",       // contains challenge == base64url(SHA-256(JCS(inner)))
  "signature": "base64url",            // over authenticatorData || SHA-256(clientDataJSON)
  "publicKey": "base64url(COSE)"       // the registered passkey public key (COSE_Key)
}
```

A verifier checks the human proof by: (a) decoding `clientDataJSON`, asserting
`type=="webauthn.get"` and `challenge == base64url(SHA-256(JCS(inner)))`; (b) verifying `signature`
over `authenticatorData || SHA-256(clientDataJSON)` against `publicKey`.

## 6. Scope

Scope strings are opaque `action:resource` tokens agreed between issuer and verifier. The verifier
checks set-membership: a requested action MUST be exactly present in `scope`. v1 does **not** define
wildcards or hierarchies (reserved). Recommended convention: lowercase `verb:noun`
(`read:calendar`, `post:linkedin`, `book:flights`).

## 7. Revocation

The `credentialStatus.id` URL returns:

```json
{ "mandateId": "urn:uuid:5f3b...", "revoked": false, "revokedAt": null }
```

A verifier MUST treat the mandate as invalid if `revoked == true`. v1 uses a per-mandate endpoint
for clarity. v2 SHOULD migrate to [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
for privacy (group anonymity) and scale — the `statusListIndex` / `statusListCredential` fields are
already reserved. Verifiers SHOULD fail **closed** on a status-endpoint error unless explicitly
configured otherwise (the result carries a `degraded` flag, §9).

## 8. Passport token (transport)

The full credential is encoded as a **VC-JWT** (compact JWS, `EdDSA`):

- **Header:** `{ "alg": "EdDSA", "typ": "vc+jwt", "kid": "<issuer did:key>" }`
- **Payload:** the full credential under the `vc` claim, plus registered claims mirrored for
  convenience: `iss` (=issuer), `jti` (=mandate id), `nbf` (=validFrom), `exp` (=validUntil),
  `sub` (=agent id).
- The agent presents it as: `Authorization: Mandate <jwt>`.

## 9. Verification result

A conformant verifier returns:

```jsonc
{
  "valid": true,
  "checks": {
    "issuerSignature": true,   // VC-JWT EdDSA verified against did:key
    "humanProof":      true,   // WebAuthn assertion verified over challenge
    "notExpired":      true,   // now within [validFrom, validUntil]
    "notRevoked":      true,   // status endpoint says revoked=false
    "scope":           true    // required action ∈ scope (if a required scope was given)
  },
  "degraded": false,           // true if status check could not be completed
  "mandate": { /* decoded credential */ },
  "reason": null               // first failing check name when valid=false
}
```

`valid` is the AND of all performed checks. If any check fails, `valid=false` and `reason` names
the first failure.

## 10. Threat model

### What a verified mandate DOES guarantee
- **Human authorization of this exact mandate.** A WebAuthn private key controlled by a human
  signed `SHA-256(JCS(inner mandate))`. The agent cannot alter scope, expiry or subject without
  invalidating the human proof.
- **Issuer attestation.** A specific issuer (`did:key`) signed the credential and stands behind its
  revocation endpoint. With issuer pinning, the verifier knows *which* issuer.
- **Bounded authority.** The action is within an explicit `scope`, the mandate is within
  `[validFrom, validUntil]`, and it has not been revoked at check time.
- **Tamper evidence.** Any change to the token breaks the issuer signature; any change to the
  mandate body breaks the human proof.

### What it does NOT guarantee (by design)
- **Not proof-of-personhood / uniqueness.** It proves *a* human authorized the agent, not *which*
  human, nor that they are unique. **Non-transferability is unsolved:** a human can lend or rent
  their passkey. We provide *mandate + scope + revocation* (accountability), **not** a uniqueness
  proof. Proof-of-personhood is inherited from an external root (World ID, etc.), never minted here.
- **WebAuthn is used for signing, not session auth.** The assertion authenticates *a mandate*, not
  a login. Consequently the verifier checks the challenge binding, signature, and User-Present flag,
  but **deliberately does not pin `origin` / `rpIdHash`** — the credential is meant to be portable
  and verifiable by any party, not tied to one Relying Party. A verifier that wants RP-binding must
  add `expectedOrigin` / `expectedRpId` checks on top. Verifiers MUST re-derive the challenge from
  the mandate and never trust the embedded `challenge` blindly.
- **Bearer token / replay.** A leaked token is usable until it expires or is revoked. Verifiers
  needing per-action freshness MUST add a nonce or transaction binding at the application layer
  (reserved for v2).

### Operational requirements for deployers
- **Revocation must be authenticated.** The revoke action MUST be authorized — only the human who
  authorized the mandate (or the issuer admin) may revoke it — and SHOULD be audit-logged. *The
  reference demo server leaves `/revoke` open purely to keep the demo one-click; do not copy that.*
- **Pin the issuer, or harden status fetching.** `credentialStatus.id` is taken from the
  (only signature-verified) token. A verifier that does not pin `expected_issuer` and blindly
  fetches that URL is exposed to SSRF. The SDK's default resolver mitigates this (HTTPS-only, no
  redirects, blocks private/loopback/link-local hosts), but production verifiers SHOULD pin trusted
  issuers and resolve status through an allowlisted path.
- **Issuer scope policy.** An issuer SHOULD constrain grantable `scope` per human/agent/org rather
  than echoing client input.
- **Protect the issuer key.** It is the issuance trust anchor. Compromise lets an attacker mint
  mandates, but **not** forge the human proof of an uncompromised human.

## 11. Security considerations

- **WebAuthn-as-signing** is used outside its canonical session-auth intent. Verifiers MUST
  re-derive and compare the challenge to the mandate hash — never trust the embedded challenge blindly.
- **No private keys leave the human's authenticator.** The issuer never sees the passkey private key.
- **Non-transferability of the human root is NOT solved** (a human may lend their passkey). v1
  provides *mandate + scope + revocation* (accountability), not proof of uniqueness. ZK selective
  disclosure and proof-of-personhood binding are future work.
- **Replay:** mandates are bearer tokens. Verifiers needing per-action freshness SHOULD add a
  nonce/transaction binding at the application layer (reserved for v2).
- **Issuer key** is the issuance trust anchor; protect it. Compromise allows minting mandates but
  not forging the human proof.

## 12. Versioning

This document is `v1`. Breaking changes bump the `https://agentpassport.dev/vN` context URL and the
`AgentMandate` type. Verifiers MUST reject contexts/types they do not understand.
