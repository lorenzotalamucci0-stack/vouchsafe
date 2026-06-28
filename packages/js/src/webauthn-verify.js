// Verify a WebAuthn assertion used as a signature over the inner mandate.

import { b64uDecode, b64uEncode, mandateHash, sha256 } from "./jcs.js";

const ES256 = -7;
const EDDSA = -8;
const RS256 = -257;

// WebAuthn ES256 signatures are ASN.1 DER; WebCrypto ECDSA wants raw r||s (P1363).
function derToRaw(der) {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error("bad DER: no SEQUENCE");
  if (der[offset] & 0x80) offset += 1 + (der[offset] & 0x7f); // long-form length
  else offset += 1;
  const readInt = () => {
    if (der[offset++] !== 0x02) throw new Error("bad DER: no INTEGER");
    let len = der[offset++];
    let val = der.slice(offset, offset + len);
    offset += len;
    while (val.length > 0 && val[0] === 0x00) val = val.slice(1); // strip sign padding
    return val;
  };
  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

async function verifySignature(spki, alg, signature, signed) {
  if (alg === ES256) {
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(signature), signed);
  }
  if (alg === EDDSA) {
    const key = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "Ed25519" }, key, signature, signed);
  }
  if (alg === RS256) {
    const key = await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, signed);
  }
  return false;
}

export async function verifyHumanProof(inner, humanProof) {
  let authenticatorData, clientDataBytes, signature, spki, alg;
  try {
    authenticatorData = b64uDecode(humanProof.authenticatorData);
    clientDataBytes = b64uDecode(humanProof.clientDataJSON);
    signature = b64uDecode(humanProof.signature);
    spki = b64uDecode(humanProof.publicKey);
    alg = humanProof.alg ?? ES256;
  } catch (e) {
    return { ok: false, reason: "malformed humanProof" };
  }

  let clientData;
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  } catch (e) {
    return { ok: false, reason: "invalid clientDataJSON" };
  }
  if (clientData.type !== "webauthn.get") return { ok: false, reason: "clientDataJSON.type is not webauthn.get" };

  const expected = b64uEncode(await mandateHash(inner));
  if (clientData.challenge !== expected) return { ok: false, reason: "challenge does not match mandate hash" };

  const clientHash = await sha256(clientDataBytes);
  const signed = new Uint8Array([...authenticatorData, ...clientHash]);
  try {
    const ok = await verifySignature(spki, alg, signature, signed);
    return ok ? { ok: true } : { ok: false, reason: "WebAuthn signature is invalid" };
  } catch (e) {
    return { ok: false, reason: "WebAuthn signature is invalid" };
  }
}
