// Agent Passport JS SDK — issue / present / verify / revoke.
// verify() runs in Node 20+ and modern browsers (WebCrypto); it interoperates with
// tokens issued by the Python SDK.

import { b64uDecode } from "./jcs.js";
import { didToRawEd25519 } from "./didkey.js";
import { signCompactJws, verifyCompactJws } from "./ed25519.js";
import { verifyHumanProof } from "./webauthn-verify.js";

const AUTH_SCHEME = "Mandate";

export function present(token) {
  return { Authorization: `${AUTH_SCHEME} ${token}` };
}

export function extractToken(header) {
  if (!header) return null;
  const [scheme, value] = header.split(" ", 2);
  return scheme === AUTH_SCHEME ? value : null;
}

// Issue a passport token (Node issuer side). `privateKey` is a WebCrypto Ed25519 CryptoKey.
export async function issue(innerMandate, humanProof, { privateKey, issuerDid }) {
  if (innerMandate.issuer !== issuerDid) throw new Error("inner mandate issuer mismatch");
  const credential = { ...innerMandate, humanProof };
  const epoch = (ts) => Math.floor(Date.parse(ts) / 1000);
  const payload = {
    iss: issuerDid,
    jti: innerMandate.id,
    sub: innerMandate.credentialSubject.id,
    nbf: epoch(innerMandate.validFrom),
    exp: epoch(innerMandate.validUntil),
    vc: credential,
  };
  return signCompactJws(payload, { alg: "EdDSA", typ: "vc+jwt", kid: issuerDid }, privateKey);
}

// Block obvious private/loopback literals (full DNS-rebinding defense needs a server-side resolver).
function isPrivateHost(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true;
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || (a === 169 && b === 254) || (a === 192 && b === 168) ||
        (a === 172 && b >= 16 && b <= 31) || a === 0) return true;
  }
  return false;
}

// Default revocation resolver: GET credentialStatus.id. SSRF-hardened (https, no redirects,
// timeout, private hosts blocked). credentialStatus.id is token-controlled, so pin the issuer.
async function httpStatusResolver(statusEntry, { allowInsecure = false, timeoutMs = 5000 } = {}) {
  const url = new URL(statusEntry.id);
  if (url.protocol !== "https:" && !allowInsecure) throw new Error("status URL must be https (allowInsecure for local dev)");
  if (!allowInsecure && isPrivateHost(url.hostname)) throw new Error("status host is private/loopback");
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { redirect: "error", signal: ctrl.signal });
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

export async function verify(token, opts = {}) {
  const {
    requiredScope = null,
    expectedIssuer = null,
    statusResolver = httpStatusResolver,
    checkRevocation = true,
    failClosed = true,
    now = new Date(),
  } = opts;

  const checks = {};
  const finalize = (extra = {}) => {
    const reason = Object.entries(checks).find(([, ok]) => !ok)?.[0] ?? null;
    return { valid: reason === null, checks, reason, ...extra };
  };

  // Read issuer DID (unverified) to get its public key.
  let unverified, issuerDid, rawPub;
  try {
    unverified = JSON.parse(new TextDecoder().decode(b64uDecode(token.split(".")[1])));
    issuerDid = unverified.iss;
    rawPub = didToRawEd25519(issuerDid);
  } catch (e) {
    throw new Error(`cannot read token: ${e.message}`);
  }

  // 1. Issuer signature (alg pinned to EdDSA; kid must match the issuer DID).
  let payload;
  try {
    const res = await verifyCompactJws(token, rawPub);
    checks.issuerSignature = res.ok && (res.header.kid === undefined || res.header.kid === issuerDid);
    payload = res.payload;
  } catch (e) {
    throw new Error(`invalid token: ${e.message}`);
  }
  if (!checks.issuerSignature) return finalize();

  const credential = payload.vc;
  if (!credential || !credential.humanProof) throw new Error("token has no embedded credential/humanProof");

  // 2. Trusted issuer (only if pinned).
  if (expectedIssuer !== null) {
    checks.trustedIssuer = issuerDid === expectedIssuer;
    if (!checks.trustedIssuer) return finalize({ mandate: credential });
  }

  const { humanProof, ...inner } = credential;

  // 3. Human proof.
  const proof = await verifyHumanProof(inner, humanProof);
  checks.humanProof = proof.ok;
  if (!proof.ok) return finalize({ mandate: credential });

  // 4. Not expired.
  const from = Date.parse(inner.validFrom);
  const until = Date.parse(inner.validUntil);
  checks.notExpired = from <= now.getTime() && now.getTime() <= until;
  if (!checks.notExpired) return finalize({ mandate: credential });

  // 5. Not revoked.
  let degraded = false;
  if (checkRevocation) {
    try {
      const status = await statusResolver(inner.credentialStatus);
      checks.notRevoked = !status.revoked;
    } catch (e) {
      degraded = true;
      checks.notRevoked = !failClosed;
    }
    if (!checks.notRevoked) return finalize({ degraded, mandate: credential });
  }

  // 6. Scope.
  if (requiredScope !== null) {
    const required = Array.isArray(requiredScope) ? requiredScope : [requiredScope];
    const granted = new Set(inner.credentialSubject.scope || []);
    checks.scope = required.every((s) => granted.has(s));
  }

  return finalize({ degraded, mandate: credential });
}

// Revoke via the issuer's /revoke endpoint.
export async function revoke(mandateId, { baseUrl }) {
  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mandateId }),
  });
  return res.json();
}
