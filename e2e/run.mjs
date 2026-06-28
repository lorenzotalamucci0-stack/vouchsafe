// End-to-end demo test with a real CDP WebAuthn virtual authenticator (no physical key).
// Drives the 5 demo steps and asserts the live valid -> scope-denied -> revoked transitions.

import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.AP_BASE_URL || "http://localhost:8090";
const here = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(here, "shots");
mkdirSync(SHOTS, { recursive: true });

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "✓" : "✗"} ${name}`);
  if (!cond) failures++;
}

const browser = await chromium.launch();
const context = await browser.newContext({ baseURL: BASE });
const page = await context.newPage();
page.on("console", (m) => { if (m.type() === "error") console.log("  [console.error]", m.text()); });

// --- attach a virtual authenticator (internal platform passkey, auto user-verified) ---
const client = await context.newCDPSession(page);
await client.send("WebAuthn.enable");
await client.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    automaticPresenceSimulation: true,
    isUserVerified: true,
  },
});

const text = (sel) => page.locator(sel).innerText();
async function waitText(sel, substr, label) {
  try {
    await page.locator(sel).filter({ hasText: substr }).first().waitFor({ timeout: 8000 });
    check(label, true);
  } catch {
    check(`${label} (got: ${JSON.stringify(await text(sel).catch(() => "<none>"))})`, false);
  }
}

// Run an agent action and assert on the VERDICT line (carries the unique reason),
// clearing the panel first so we never match a stale previous result.
async function act(action, verdictSubstr, label) {
  await page.evaluate(() => { document.getElementById("out-act").innerHTML = ""; });
  await page.locator("#action").selectOption(action);
  await page.getByRole("button", { name: /Esegui l'azione/ }).click();
  try {
    await page.locator("#out-act .verdict").filter({ hasText: verdictSubstr }).first()
      .waitFor({ timeout: 8000 });
    check(label, true);
  } catch {
    const got = await page.locator("#out-act .verdict").innerText().catch(() => "<none>");
    check(`${label} (verdict: ${JSON.stringify(got)})`, false);
  }
  await page.waitForTimeout(400); // let the fade-in settle before any screenshot
}

await page.goto(BASE);
check("page loaded", (await page.title()).includes("Vouchsafe"));

// Step 1 — register passkey
await page.getByRole("button", { name: /Crea passaporto/ }).click();
await waitText("#out-register", "Passaporto creato", "step1: passport created");

// Step 2 — issue mandate (default scope: read:calendar + book:flights)
await page.getByRole("button", { name: /Firma il mandato/ }).click();
await waitText("#out-issue", "Mandato attivo", "step2: mandate issued");

// Step 3a — in-scope action -> valid
await act("book:flights", "Azione eseguita", "step3a: in-scope action ACCEPTED");
await page.screenshot({ path: path.join(SHOTS, "act-valid.png") });

// Step 3b — out-of-scope action -> denied (reason: out of permissions)
await act("post:linkedin", "permessi", "step3b: out-of-scope action DENIED (scope)");
await page.screenshot({ path: path.join(SHOTS, "act-scope-denied.png") });

// Step 4 — revoke
await page.getByRole("button", { name: /Revoca il mandato/ }).click();
await waitText("#out-revoke", "Mandato revocato", "step4: mandate revoked");

// Step 5 — in-scope action AFTER revoke -> denied (reason: revoked), in real time
await act("book:flights", "revocato", "step5: action after revoke DENIED (revoked)");
await page.screenshot({ path: path.join(SHOTS, "act-revoked.png") });

await browser.close();
console.log(failures === 0 ? "\nALL E2E CHECKS PASSED" : `\n${failures} E2E CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
