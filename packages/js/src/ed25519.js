// Ed25519 issuer signature over the VC-JWT, via WebCrypto (Node 20+ and modern browsers).

import { b64uDecode, b64uEncode } from "./jcs.js";

export async function importPublicKey(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

export async function importPrivateKeyPkcs8(pkcs8) {
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

// Verify a compact JWS (header.payload.signature) with an Ed25519 raw public key.
export async function verifyCompactJws(token, rawPublicKey) {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) throw new Error("malformed JWT");
  const key = await importPublicKey(rawPublicKey);
  const signed = new TextEncoder().encode(`${h}.${p}`);
  const sig = b64uDecode(s);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, signed);
  return { ok, header: JSON.parse(new TextDecoder().decode(b64uDecode(h))), payload: JSON.parse(new TextDecoder().decode(b64uDecode(p))) };
}

// Sign a payload as a compact EdDSA JWS (Node issuer side).
export async function signCompactJws(payload, header, privateKey) {
  const enc = (obj) => b64uEncode(new TextEncoder().encode(JSON.stringify(obj)));
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64uEncode(new Uint8Array(sig))}`;
}
