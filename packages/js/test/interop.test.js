// Cross-SDK interop: a token minted by the Python SDK must verify with the JS SDK.
// This proves the JCS canonicalization, Ed25519 issuer signature, and ES256 WebAuthn
// proof (DER->raw) all agree byte-for-byte across languages.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { verify, present, extractToken } from "../src/index.js";

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
  const tampered = `${h}.${p}.${s.slice(0, -2)}${s.slice(-2) === "AB" ? "CD" : "AB"}`;
  const result = await verify(tampered, { statusResolver: offlineStatus(false) });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "issuerSignature");
});

test("present / extractToken round-trip", () => {
  assert.equal(extractToken(present("abc.def.ghi").Authorization), "abc.def.ghi");
});
