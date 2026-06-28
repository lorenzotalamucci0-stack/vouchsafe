// Verify a WebAuthn assertion used as a signature over the inner mandate.

import { b64uDecode, b64uEncode, mandateHash, sha256 } from "./jcs.js";

const ES256 = -7;
const EDDSA = -8;
const RS256 = -257;

// WebAuthn ES256 signatures are ASN.1 DER; WebCrypto ECDSA wants raw r||s (P1363).
// Strict parse: validate the SEQUENCE length consumes exactly the buffer, INTEGERs use
// minimal encoding, r/s fit in 32 bytes, and there is no trailing data.
function derToRaw(der) {
  let offset = 0;
  const readLen = () => {
    let len = der[offset++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 2) throw new Error("bad DER: unsupported length form");
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | der[offset++];
    }
    return len;
  };
  if (der[offset++] !== 0x30) throw new Error("bad DER: no SEQUENCE");
  const seqLen = readLen();
  if (offset + seqLen !== der.length) throw new Error("bad DER: SEQUENCE length mismatch / trailing data");
  const readInt = () => {
    if (der[offset++] !== 0x02) throw new Error("bad DER: no INTEGER");
    const len = readLen();
    let val = der.slice(offset, offset + len);
    offset += len;
    if (val.length === 0) throw new Error("bad DER: empty INTEGER");
    // Minimal encoding: a leading 0x00 is only allowed to clear a high sign bit.
    if (val.length > 1 && val[0] === 0x00 && (val[1] & 0x80) === 0) throw new Error("bad DER: non-minimal INTEGER");
    if (val[0] & 0x80) throw new Error("bad DER: negative INTEGER");
    if (val.length > 1 && val[0] === 0x00) val = val.slice(1);
    if (val.length > 32) throw new Error("bad DER: INTEGER too large for P-256");
    return val;
  };
  const r = readInt();
  const s = readInt();
  if (offset !== der.length) throw new Error("bad DER: trailing data after INTEGERs");
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

  // authenticatorData: rpIdHash(32) | flags(1) | signCount(4). Require User Present (UP, bit 0).
  if (authenticatorData.length < 37) return { ok: false, reason: "authenticatorData too short" };
  if ((authenticatorData[32] & 0x01) === 0) return { ok: false, reason: "User Present flag not set" };

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
