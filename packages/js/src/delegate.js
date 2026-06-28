// Delegation chain (Pilastro 1.5) — verify a chain of re-delegated mandates, and sign a
// narrower child (Node). Mirrors the Python SDK; reuses verify() for the human-signed root.

import { b64uDecode } from "./jcs.js";
import { didToRawEd25519 } from "./didkey.js";
import { signCompactJws, verifyCompactJws } from "./ed25519.js";
import { verify } from "./index.js";

const VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://vouchsafe.dev/v1"];
const MANDATE_TYPE = ["VerifiableCredential", "AgentMandate"];

const payloadOf = (t) => JSON.parse(new TextDecoder().decode(b64uDecode(t.split(".")[1])));
const vcOf = (t) => payloadOf(t).vc;
const linkOf = (vc, kind) => ({ agent: vc.credentialSubject.id, agentName: vc.credentialSubject.agentName,
  scope: vc.credentialSubject.scope || [], validUntil: vc.validUntil, kind });
const subset = (a, b) => a.every((x) => b.includes(x));

export async function verifyChain(token, opts = {}) {
  return _node(token, opts.requiredScope ?? null, 0, opts);
}

async function _node(token, requiredScope, depth, opts) {
  const vc = vcOf(token);
  const now = opts.now ? opts.now.getTime() : Date.now();

  if (!("delegatedFrom" in vc)) {
    const res = await verify(token, {
      requiredScope, expectedIssuer: opts.expectedIssuer ?? null, statusResolver: opts.statusResolver,
      checkRevocation: opts.checkRevocation ?? true, failClosed: opts.failClosed ?? true, now: opts.now,
    });
    return { valid: res.valid, reason: res.reason, depth, links: [linkOf(vc, "root")] };
  }
  const leaf = linkOf(vc, "delegated");
  if (depth >= (opts.maxDepth ?? 6)) return { valid: false, reason: "depthExceeded", depth, links: [leaf] };

  const iss = payloadOf(token).iss;
  let ok = false;
  try { const r = await verifyCompactJws(token, didToRawEd25519(iss)); ok = r.ok && (r.header.kid === undefined || r.header.kid === iss); } catch { ok = false; }
  if (!ok) return { valid: false, reason: "childSignature", depth, links: [leaf] };

  const parent = await _node(vc.delegatedFrom, null, depth + 1, opts);
  if (!parent.valid) return { valid: false, reason: parent.reason, depth, links: [leaf, ...parent.links] };

  const pvc = vcOf(vc.delegatedFrom), ps = pvc.credentialSubject, cs = vc.credentialSubject;
  let reason = null;
  // SPEC §12: every link — not just the root — MUST be a recognized context/type.
  const ctx = vc["@context"] || [], typ = vc.type || [];
  if (!(ctx.includes("https://vouchsafe.dev/v1") && typ.includes("AgentMandate"))) reason = "recognizedFormat";
  else if (!(iss === ps.id && ps.id === vc.issuer)) reason = "childBinding";
  else if (!subset(cs.scope || [], ps.scope || [])) reason = "scopeNarrowing";
  else if (Date.parse(vc.validUntil) > Date.parse(pvc.validUntil)) reason = "expiryNarrowing";
  else if (!(Date.parse(vc.validFrom) <= now && now <= Date.parse(vc.validUntil))) reason = "notExpired";
  else {
    if ((opts.checkRevocation ?? true) && vc.credentialStatus) {
      try { const st = opts.statusResolver ? await opts.statusResolver(vc.credentialStatus) : { revoked: false }; if (st.revoked) reason = "notRevoked"; }
      catch { reason = (opts.failClosed ?? true) ? "notRevoked" : null; }
    }
    if (reason === null && requiredScope !== null) {
      const req = Array.isArray(requiredScope) ? requiredScope : [requiredScope];
      if (!req.every((x) => (cs.scope || []).includes(x))) reason = "scope";
    }
  }
  return { valid: reason === null, reason, depth, links: [leaf, ...parent.links] };
}

// Sign a narrower child mandate (Node). privateKey = parent agent Ed25519 CryptoKey.
export async function signChildMandate(parentToken, { childAgentId, scope, ttlSeconds, privateKey, parentAgentDid, statusBaseUrl = "https://vouchsafe.dev" }) {
  const pvc = vcOf(parentToken), ps = pvc.credentialSubject;
  if (ps.id !== parentAgentDid) throw new Error("parent key does not match the parent mandate subject");
  if (!scope.length || !subset(scope, ps.scope || [])) throw new Error("child scope must be a non-empty subset of the parent scope");
  const now = Date.now();
  const until = Math.min(now + ttlSeconds * 1000, Date.parse(pvc.validUntil));
  if (until <= now) throw new Error("parent mandate already expired");
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
  const mid = `urn:uuid:${crypto.randomUUID()}`, base = statusBaseUrl.replace(/\/$/, "");
  const inner = {
    "@context": VC_CONTEXT, type: MANDATE_TYPE, id: mid, issuer: parentAgentDid,
    validFrom: iso(now), validUntil: iso(until),
    credentialStatus: { type: "AgentPassportStatus", id: `${base}/status/${mid.split(":").pop()}`, statusListCredential: `${base}/status-list` },
    credentialSubject: { id: childAgentId, agentName: `${ps.agentName || "Agent"} › sub-agente`, scope: [...scope], authorizedBy: ps.authorizedBy || {} },
    delegationDepth: (pvc.delegationDepth || 0) + 1, delegatedFrom: parentToken,
  };
  const payload = { iss: parentAgentDid, jti: mid, sub: childAgentId, nbf: Math.floor(now / 1000), exp: Math.floor(until / 1000), vc: inner };
  return signCompactJws(payload, { alg: "EdDSA", typ: "mandate+jwt", kid: parentAgentDid }, privateKey);
}
