// Cross-SDK interop: a delegation chain minted by Python must verify with the JS SDK.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { verifyChain } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const pyRoot = path.resolve(here, "../../python");
const py = path.join(pyRoot, ".venv/bin/python");
const mint = () => JSON.parse(execFileSync(py, [path.join(pyRoot, "tools/mint_chain_fixture.py")], { encoding: "utf8" }));
const status = (revoked) => async () => ({ revoked });

test("Python delegation chain verifies VALID in JS", async () => {
  const fx = mint();
  const r = await verifyChain(fx.child, { requiredScope: "book:flights",
    expectedIssuer: fx.expectedIssuer, statusResolver: status(false) });
  assert.equal(r.valid, true, r.reason);
  assert.deepEqual(r.links.map((l) => l.kind), ["delegated", "root"]);
});

test("out-of-scope action on the child -> denied", async () => {
  const fx = mint();
  const r = await verifyChain(fx.child, { requiredScope: "post:linkedin", statusResolver: status(false) });
  assert.equal(r.valid, false);
  assert.equal(r.reason, "scope");
});

test("revoked parent cascades -> child invalid", async () => {
  const fx = mint();
  // resolver marks the ROOT revoked (child status unknown -> treated live here returns not revoked)
  const resolver = async (entry) => ({ revoked: entry.id.endsWith(fx.rootId.split(":").pop()) });
  const r = await verifyChain(fx.child, { statusResolver: resolver });
  assert.equal(r.valid, false);
  assert.equal(r.reason, "notRevoked");
});
