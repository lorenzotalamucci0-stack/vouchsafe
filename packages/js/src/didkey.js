// did:key for Ed25519 (multicodec 0xed01, multibase base58btc), matching the Python SDK.

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_MULTICODEC = [0xed, 0x01];

export function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    const rem = Number(n % 58n);
    n = n / 58n;
    out = B58[rem] + out;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

export function b58decode(str) {
  let n = 0n;
  for (const ch of str) n = n * 58n + BigInt(B58.indexOf(ch));
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n = n / 256n;
  }
  for (const ch of str) {
    if (ch === "1") bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
}

export function didToRawEd25519(did) {
  if (!did.startsWith("did:key:z")) throw new Error("unsupported DID (expected did:key base58btc)");
  const decoded = b58decode(did.slice("did:key:z".length));
  if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    throw new Error("did:key is not an Ed25519 key");
  }
  return decoded.slice(2);
}

export function rawEd25519ToDid(raw) {
  const buf = new Uint8Array([...ED25519_MULTICODEC, ...raw]);
  return "did:key:z" + b58encode(buf);
}
