// E2E (Pilastro 2): act -> content+receipt VALID -> revoke -> content REVOKED in real time.
// Real CDP WebAuthn virtual authenticator. Reads verdicts from the live DOM.

import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.AP_BASE_URL || "http://localhost:8090";
const here = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(here, "shots");
mkdirSync(SHOTS, { recursive: true });

let failures = 0;
const check = (name, cond) => { console.log(`${cond ? "✓" : "✗"} ${name}`); if (!cond) failures++; };

const browser = await chromium.launch();
const context = await browser.newContext({ baseURL: BASE, viewport: { width: 1100, height: 800 } });
const page = await context.newPage();
page.on("console", (m) => { if (m.type() === "error") console.log("  [console.error]", m.text()); });

const client = await context.newCDPSession(page);
await client.send("WebAuthn.enable");
await client.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true },
});

async function waitText(sel, substr, label) {
  try {
    await page.locator(sel).filter({ hasText: substr }).first().waitFor({ timeout: 8000 });
    check(label, true);
  } catch {
    const got = await page.locator(sel).innerText().catch(() => "<none>");
    check(`${label} (got: ${JSON.stringify(got)})`, false);
  }
}

async function verifyContent(verdictSubstr, label) {
  await page.evaluate(() => { document.getElementById("out-verify").innerHTML = ""; });
  await page.getByRole("button", { name: /Verifica contenuto/ }).click();
  try {
    await page.locator("#out-verify .verdict").filter({ hasText: verdictSubstr }).first().waitFor({ timeout: 8000 });
    check(label, true);
  } catch {
    const got = await page.locator("#out-verify .verdict").innerText().catch(() => "<none>");
    check(`${label} (verdict: ${JSON.stringify(got)})`, false);
  }
}

await page.goto(BASE);
check("page loaded", (await page.title()).includes("Agent Passport"));

await page.getByRole("button", { name: /Crea passaporto/ }).click();
await waitText("#out-register", "human root", "register passport");

await page.getByRole("button", { name: /Genera mandato/ }).click();
await waitText("#out-issue", "Mandato emesso", "issue mandate");

// Agent acts (in-scope) -> content + receipt produced
await page.locator("#action").selectOption("book:flights");
await page.getByRole("button", { name: /esegue l'azione/ }).click();
await waitText("#out-act", "AZIONE ESEGUITA", "agent acted, content produced");
await waitText("#out-verify", "ricevuta pronta", "receipt prefilled");

// Verify content+receipt -> VALID
await verifyContent("CONTENUTO VALIDO", "content+receipt VALID");
await page.screenshot({ path: path.join(SHOTS, "content-valid.png") });

// Revoke the mandate
await page.getByRole("button", { name: /Revoca il mandato/ }).click();
await waitText("#out-revoke", "REVOCATO", "mandate revoked");

// Re-verify the SAME content+receipt -> now REVOKED, in real time
await verifyContent("notRevoked", "content REVOKED after revoke (notRevoked)");
await page.screenshot({ path: path.join(SHOTS, "content-revoked.png") });

await browser.close();
console.log(failures === 0 ? "\nALL RECEIPT E2E CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
