// Cross-SDK interop: a token minted by the Python SDK must verify with the JS SDK.
// This proves the JCS canonicalization, Ed25519 issuer signature, and ES256 WebAuthn
// proof (DER->raw) all agree byte-for-byte across languages.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { verify, present, extractToken } from "../src/index.js";
import { b64uDecode, b64uEncode, canonicalize } from "../src/jcs.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const pyRoot = path.resolve(here, "../../python");
const py = path.join(pyRoot, ".venv/bin/python");

function mint() {
  const out = execFileSync(py, [path.join(pyRoot, "tools/mint_fixture.py")], { encoding: "utf8" });
  return JSON.parse(out);
}

const offlineStatus = (revoked) => async () => ({ revoked });

test("Python-issued token verifies as VALID in JS", async () => {
  const fx = mint();
  const result = await verify(fx.token, {
    requiredScope: "book:flights",
    expectedIssuer: fx.issuerDid,
    statusResolver: offlineStatus(false),
  });
  assert.equal(result.valid, true, JSON.stringify(result.checks));
  assert.deepEqual(result.checks, {
    issuerSignature: true,
    trustedIssuer: true,
    humanProof: true,
    notExpired: true,
    notRevoked: true,
    scope: true,
  });
});

test("revoked status -> invalid", async () => {
  const fx = mint();
  const result = await verify(fx.token, { statusResolver: offlineStatus(true) });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "notRevoked");
});

test("out-of-scope -> invalid", async () => {
  const fx = mint();
  const result = await verify(fx.token, {
    requiredScope: "post:linkedin",
    statusResolver: offlineStatus(false),
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "scope");
});

test("tampered issuer signature -> invalid", async () => {
  const fx = mint();
  const [h, p, s] = fx.token.split(".");
  const sig = b64uDecode(s);
  sig[0] ^= 0x01;                       // flip a byte -> signature deterministically invalid
  const tampered = `${h}.${p}.${b64uEncode(sig)}`;
  const result = await verify(tampered, { statusResolver: offlineStatus(false) });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "issuerSignature");
});

test("present / extractToken round-trip", () => {
  assert.equal(extractToken(present("abc.def.ghi").Authorization), "abc.def.ghi");
});

test("JCS canonical bytes match the Python frozen vector (cross-language)", () => {
  // Same object and expected string as packages/python tests/test_hardening.py::test_jcs_known_vector
  const obj = { b: 2, a: "x", nested: { z: [1, 2, 3], emoji: "😀" } };
  const expected = '{"a":"x","b":2,"nested":{"emoji":"😀","z":[1,2,3]}}';
  assert.equal(new TextDecoder().decode(canonicalize(obj)), expected);
});

test("JCS rejects big ints and non-BMP keys", () => {
  assert.throws(() => canonicalize({ n: Number.MAX_SAFE_INTEGER + 1 }));
  assert.throws(() => canonicalize({ "\u{10000}": 1 }));
});
