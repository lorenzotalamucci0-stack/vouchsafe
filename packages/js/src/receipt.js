// Content Receipt (Pilastro 2) — sign/verify a signed receipt binding an agent's output
// to its mandate. Reuses verify() (mandate, incl. live revocation) from index.js.

import { b64uDecode, sha256 } from "./jcs.js";
import { didToRawEd25519 } from "./didkey.js";
import { signCompactJws, verifyCompactJws } from "./ed25519.js";
import { verify } from "./index.js";

const RECEIPT_TYPE = ["VerifiableCredential", "ContentReceipt"];
const VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://vouchsafe.dev/v1"];

function bytesToHex(u8) {
  return [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function outputHash(outputBytes) {
  return bytesToHex(await sha256(outputBytes instanceof Uint8Array ? outputBytes : new Uint8Array(outputBytes)));
}

// Sign a Content Receipt (Node agent side). privateKey is a WebCrypto Ed25519 CryptoKey.
export async function signReceipt(outputBytes, mandateToken, { privateKey, agentDid, scope, mandateId }) {
  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const receiptId = `urn:uuid:${crypto.randomUUID()}`;
  const bytes = outputBytes instanceof Uint8Array ? outputBytes : new Uint8Array(outputBytes);
  const credential = {
    "@context": VC_CONTEXT,
    type: RECEIPT_TYPE,
    id: receiptId,
    issuer: agentDid,
    validFrom: now,
    credentialSubject: {
      agentId: agentDid,
      mandateId,
      scope,
      output: { hashAlg: "sha-256", hash: await outputHash(bytes), bytes: bytes.length },
      producedAt: now,
    },
    mandate: mandateToken,
  };
  const payload = { iss: agentDid, jti: receiptId, sub: agentDid, vc: credential };
  return signCompactJws(payload, { alg: "EdDSA", typ: "receipt+jwt", kid: agentDid }, privateKey);
}

export async function verifyReceipt(outputBytes, receiptToken, opts = {}) {
  const checks = {};
  const finalize = (extra = {}) => {
    const reason = Object.entries(checks).find(([, ok]) => !ok)?.[0] ?? null;
    return { valid: reason === null, checks, reason, ...extra };
  };

  // Read agent DID (unverified) and verify the receipt signature against it.
  let agentDid, rawPub;
  try {
    const unverified = JSON.parse(new TextDecoder().decode(b64uDecode(receiptToken.split(".")[1])));
    agentDid = unverified.iss;
    rawPub = didToRawEd25519(agentDid);
  } catch (e) {
    throw new Error(`cannot read receipt: ${e.message}`);
  }

  // 1. Receipt signature.
  let res;
  try {
    res = await verifyCompactJws(receiptToken, rawPub);
  } catch (e) {
    throw new Error(`invalid receipt: ${e.message}`);
  }
  checks.receiptSignature = res.ok && (res.header.kid === undefined || res.header.kid === agentDid);
  if (!checks.receiptSignature) return finalize();

  const credential = res.payload.vc;
  if (!credential || JSON.stringify(credential.type) !== JSON.stringify(RECEIPT_TYPE)) {
    throw new Error("not a ContentReceipt");
  }
  const subject = credential.credentialSubject || {};
  const out = subject.output || {};
  const mandateToken = credential.mandate;
  if (typeof mandateToken !== "string") throw new Error("receipt has no embedded mandate");

  // 1b. Internal claim consistency: signed JWS claims must agree with the VC.
  checks.receiptClaims =
    credential.issuer === agentDid && res.payload.sub === agentDid && res.payload.jti === credential.id;
  if (!checks.receiptClaims) return finalize({ receipt: credential });

  // 2. Output hash matches the exact bytes.
  checks.outputHash = out.hashAlg === "sha-256" && out.hash === (await outputHash(outputBytes));
  if (!checks.outputHash) return finalize({ receipt: credential });

  // 3 + 4. Verify the embedded mandate (issuer sig, human proof, expiry, revocation, scope).
  const mandate = await verify(mandateToken, {
    requiredScope: subject.scope,
    expectedIssuer: opts.expectedIssuer ?? null,
    statusResolver: opts.statusResolver,
    checkRevocation: opts.checkRevocation ?? true,
    failClosed: opts.failClosed ?? true,
    now: opts.now,
  });
  const mandateSubjectId = mandate.mandate?.credentialSubject?.id;
  const mandateId = mandate.mandate?.id;
  checks.agentBinding =
    agentDid === subject.agentId && agentDid === mandateSubjectId && subject.mandateId === mandateId;
  if (!checks.agentBinding) return finalize({ receipt: credential, mandate });

  Object.assign(checks, mandate.checks); // merge issuerSignature, humanProof, notExpired, notRevoked, scope
  return finalize({ degraded: mandate.degraded, receipt: credential, mandate });
}
