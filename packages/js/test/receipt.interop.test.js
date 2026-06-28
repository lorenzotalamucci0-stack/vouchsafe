// Cross-SDK interop: a Content Receipt minted by the Python SDK must verify with the JS SDK.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { verifyReceipt } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const pyRoot = path.resolve(here, "../../python");
const py = path.join(pyRoot, ".venv/bin/python");

function mint() {
  const out = execFileSync(py, [path.join(pyRoot, "tools/mint_receipt_fixture.py")], { encoding: "utf8" });
  const fx = JSON.parse(out);
  fx.content = new Uint8Array(Buffer.from(fx.contentB64, "base64"));
  return fx;
}

const offlineStatus = (revoked) => async () => ({ revoked });

test("Python-issued receipt verifies as VALID in JS", async () => {
  const fx = mint();
  const r = await verifyReceipt(fx.content, fx.receipt, {
    expectedIssuer: fx.issuerDid,
    statusResolver: offlineStatus(false),
  });
  assert.equal(r.valid, true, JSON.stringify(r.checks));
  assert.ok(r.checks.receiptSignature && r.checks.outputHash && r.checks.agentBinding);
  assert.ok(r.checks.notRevoked && r.checks.scope && r.checks.humanProof);
});

test("tampered output -> invalid (outputHash)", async () => {
  const fx = mint();
  const edited = new Uint8Array([...fx.content, 33]); // append '!'
  const r = await verifyReceipt(edited, fx.receipt, { statusResolver: offlineStatus(false) });
  assert.equal(r.valid, false);
  assert.equal(r.reason, "outputHash");
});

test("revoked mandate -> invalid (notRevoked), in real time", async () => {
  const fx = mint();
  const r = await verifyReceipt(fx.content, fx.receipt, { statusResolver: offlineStatus(true) });
  assert.equal(r.valid, false);
  assert.equal(r.reason, "notRevoked");
});

test("tampered receipt signature -> invalid (receiptSignature)", async () => {
  const fx = mint();
  const [h, p, s] = fx.receipt.split(".");
  const sig = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  sig[0] ^= 0x01;
  const s2 = sig.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const r = await verifyReceipt(fx.content, `${h}.${p}.${s2}`, { statusResolver: offlineStatus(false) });
  assert.equal(r.valid, false);
  assert.equal(r.reason, "receiptSignature");
});
