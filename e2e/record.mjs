// Record the demo flow to a video (real interaction, virtual authenticator), for the
// LinkedIn GIF. Usage: AP_BASE_URL=http://localhost:PORT node record.mjs
// Then: ffmpeg -i shots/<video>.webm -vf "fps=12,scale=900:-1:flags=lanczos" shots/demo.gif

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
  viewport: { width: 1100, height: 720 },
  recordVideo: { dir: SHOTS, size: { width: 1100, height: 720 } },
  deviceScaleFactor: 1,
});
const page = await context.newPage();

const client = await context.newCDPSession(page);
await client.send("WebAuthn.enable");
await client.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true },
});

const pause = (ms) => page.waitForTimeout(ms);
const waitOut = (sel, substr) =>
  page.locator(sel).filter({ hasText: substr }).first().waitFor({ timeout: 8000 });

async function act(action, verdict) {
  await page.evaluate(() => { document.getElementById("out-act").innerHTML = ""; });
  await page.locator("#action").selectOption(action);
  await pause(500);
  await page.getByRole("button", { name: /Esegui l'azione/ }).click();
  await page.locator("#out-act .verdict").filter({ hasText: verdict }).first().waitFor({ timeout: 8000 });
}

await page.goto(BASE);
await pause(1200);
await page.getByRole("button", { name: /Crea passaporto/ }).click();
await waitOut("#out-register", "Passaporto creato");
await pause(1500);

await page.getByRole("button", { name: /Firma il mandato/ }).click();
await waitOut("#out-issue", "Mandato attivo");
await pause(1800);

await act("book:flights", "Azione eseguita");      // valid
await pause(2600);

await act("post:linkedin", "permessi");            // out-of-scope -> denied
await pause(2400);

await page.getByRole("button", { name: /Revoca il mandato/ }).click();
await waitOut("#out-revoke", "Mandato revocato");
await pause(1800);

await act("book:flights", "revocato");             // revoked -> denied in real time
await pause(2800);

const videoPath = await page.video().path();
await context.close();
await browser.close();
console.log(videoPath);
