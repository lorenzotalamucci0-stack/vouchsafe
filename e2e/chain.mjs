// E2E (delegation): issue root -> delegate to sub-agent -> chain VALID -> revoke root ->
// chain INVALID (notRevoked cascade). Real CDP virtual authenticator.

import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.AP_BASE_URL || "http://localhost:8090";
const SHOTS = path.join(path.dirname(fileURLToPath(import.meta.url)), "shots");
mkdirSync(SHOTS, { recursive: true });

let failures = 0;
const check = (n, c) => { console.log(`${c ? "✓" : "✗"} ${n}`); if (!c) failures++; };

const browser = await chromium.launch();
const ctx = await browser.newContext({ baseURL: BASE, viewport: { width: 1100, height: 900 } });
const page = await ctx.newPage();
page.on("console", (m) => { if (m.type() === "error") console.log("  [console.error]", m.text()); });
const client = await ctx.newCDPSession(page);
await client.send("WebAuthn.enable");
await client.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal",
  hasResidentKey: true, hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true } });

const waitV = (sel, t) => page.locator(`${sel} .verdict`).filter({ hasText: t }).first().waitFor({ timeout: 8000 });

await page.goto(BASE);
check("page loaded", (await page.title()).includes("Agent Passport"));
await page.getByRole("button", { name: /Crea passaporto/ }).click();
await waitV("#out-register", "Passaporto creato"); check("register", true);
await page.getByRole("button", { name: /Firma il mandato/ }).click();
await waitV("#out-issue", "Mandato attivo"); check("issue root", true);

// Delegate to a sub-agent (narrower) -> chain valid
await page.getByRole("button", { name: /Delega a un sotto-agente/ }).click();
try { await waitV("#out-delegate", "Catena valida"); check("delegated chain VALID", true); }
catch { check(`delegated chain VALID (got ${JSON.stringify(await page.locator("#out-delegate .verdict").innerText().catch(()=>"-"))})`, false); }
await page.waitForTimeout(400);
await page.locator("#out-delegate").scrollIntoViewIfNeeded();
await page.screenshot({ path: path.join(SHOTS, "chain-valid.png") });

// Revoke the ROOT mandate -> re-verify the chain -> invalid
await page.getByRole("button", { name: /Revoca il mandato/ }).click();
await waitV("#out-revoke", "Mandato revocato"); check("root revoked", true);
await page.getByRole("button", { name: /Ri-verifica la catena/ }).click();
try { await waitV("#out-delegate", "Catena non valida"); check("chain INVALID after root revoke", true); }
catch { check(`chain INVALID (got ${JSON.stringify(await page.locator("#out-delegate .verdict").innerText().catch(()=>"-"))})`, false); }
await page.waitForTimeout(400);
await page.locator("#out-delegate").scrollIntoViewIfNeeded();
await page.screenshot({ path: path.join(SHOTS, "chain-revoked.png") });

await browser.close();
console.log(failures === 0 ? "\nALL CHAIN E2E CHECKS PASSED" : `\n${failures} CHAIN CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
