// Record the Pilastro 2 flow to video for the LinkedIn GIF:
// content+receipt VALID -> revoke -> content REVOKED in real time.

import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.AP_BASE_URL || "http://localhost:8090";
const here = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = path.join(here, "shots");
mkdirSync(SHOTS, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  baseURL: BASE,
  viewport: { width: 1100, height: 820 },
  recordVideo: { dir: SHOTS, size: { width: 1100, height: 820 } },
});
const page = await context.newPage();
const client = await context.newCDPSession(page);
await client.send("WebAuthn.enable");
await client.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true },
});

const pause = (ms) => page.waitForTimeout(ms);
const waitOut = (sel, t) => page.locator(sel).filter({ hasText: t }).first().waitFor({ timeout: 8000 });
async function verifyContent(verdict) {
  await page.evaluate(() => { document.getElementById("out-verify").innerHTML = ""; });
  await page.getByRole("button", { name: /Verifica contenuto/ }).click();
  await page.locator("#out-verify .verdict").filter({ hasText: verdict }).first().waitFor({ timeout: 8000 });
}

await page.goto(BASE);
await pause(900);
await page.getByRole("button", { name: /Crea passaporto/ }).click();
await waitOut("#out-register", "human root");
await pause(1100);
await page.getByRole("button", { name: /Genera mandato/ }).click();
await waitOut("#out-issue", "Mandato emesso");
await pause(1300);

await page.locator("#action").selectOption("book:flights");
await page.getByRole("button", { name: /esegue l'azione/ }).click();
await waitOut("#out-act", "AZIONE ESEGUITA");
await pause(1200);
await page.locator("#rc-content").scrollIntoViewIfNeeded();
await verifyContent("CONTENUTO VALIDO");
await pause(2800);

await page.getByRole("button", { name: /Revoca il mandato/ }).click();
await waitOut("#out-revoke", "REVOCATO");
await pause(1400);
await page.locator("#rc-content").scrollIntoViewIfNeeded();
await verifyContent("notRevoked");
await pause(3000);

const videoPath = await page.video().path();
await context.close();
await browser.close();
console.log(videoPath);
