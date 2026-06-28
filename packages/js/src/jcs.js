// Canonical JSON (restricted JSON profile) + base64url + SHA-256, byte-compatible
// with the Python SDK. See jcs.py for the profile rationale: no floats, integers only
// within the safe range, object keys confined to the BMP (so Python code-point sorting
// and JS UTF-16 sorting agree).
const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER;

export function canonicalize(obj) {
  return new TextEncoder().encode(_serialize(obj));
}

function _serialize(value) {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("floats not allowed in canonical mandate");
    if (Math.abs(value) > MAX_SAFE_INT) throw new Error("integer out of safe range for cross-language hashing");
    return String(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(_serialize).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    for (const k of keys) {
      for (const ch of k) {
        if (ch.codePointAt(0) > 0xffff) throw new Error("object keys must stay within the BMP");
      }
    }
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + _serialize(value[k])).join(",") + "}";
  }
  throw new Error("unsupported type in canonical mandate: " + typeof value);
}

export function b64uEncode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

export async function mandateHash(innerMandate) {
  return sha256(canonicalize(innerMandate));
}
