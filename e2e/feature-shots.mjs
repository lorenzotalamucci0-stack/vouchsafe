// Capture the new comprehension features for manual PNG review: decode panel, live
// countdown, open tooltip, and the expiry -> denied path.
import { chromium } from "playwright";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.AP_BASE_URL || "http://localhost:8090";
const SHOTS = path.join(path.dirname(fileURLToPath(import.meta.url)), "shots");

async function newPage(browser) {
  const ctx = await browser.newContext({ baseURL: BASE, viewport: { width: 1100, height: 900 } });
  const page = await ctx.newPage();
  const errs = [];
  page.on("console", (m) => { if (m.type() === "error") errs.push(m.text()); });
  const client = await ctx.newCDPSession(page);
  await client.send("WebAuthn.enable");
  await client.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2",
    transport: "internal", hasResidentKey: true, hasUserVerification: true,
    automaticPresenceSimulation: true, isUserVerified: true } });
  return { ctx, page, errs };
}

const browser = await chromium.launch();

// --- Scene A: issue (default ttl) -> decode panel + countdown + history, with a tooltip open ---
{
  const { page } = await newPage(browser);
  await page.goto(BASE);
  await page.getByRole("button", { name: /Crea passaporto/ }).click();
  await page.locator("#out-register .verdict").waitFor();
  await page.getByRole("button", { name: /Firma il mandato/ }).click();
  await page.locator("#out-issue .verdict").filter({ hasText: "Mandato attivo" }).waitFor();
  await page.locator("#out-issue details.decode summary").click(); // open "cosa c'è dentro"
  await page.locator("#tip-2").evaluate((el) => (el.hidden = false));  // show a step tooltip
  await page.waitForTimeout(1200); // let countdown tick
  await page.locator("#history-sec").scrollIntoViewIfNeeded();
  await page.screenshot({ path: path.join(SHOTS, "feat-decode.png") });
}

// --- Scene B: expiry -> action denied (notExpired) ---
{
  const { page } = await newPage(browser);
  await page.goto(BASE);
  await page.getByRole("button", { name: /Crea passaporto/ }).click();
  await page.locator("#out-register .verdict").waitFor();
  await page.fill("#ttl", "8");
  await page.getByRole("button", { name: /Firma il mandato/ }).click();
  await page.locator("#out-issue .verdict").filter({ hasText: "Mandato attivo" }).waitFor();
  await page.waitForTimeout(9000); // let it expire
  await page.locator("#action").selectOption("book:flights");
  await page.getByRole("button", { name: /Esegui l'azione/ }).click();
  await page.locator("#out-act .verdict").filter({ hasText: "scaduto" }).waitFor({ timeout: 8000 });
  await page.waitForTimeout(400);
  await page.locator("#out-act").scrollIntoViewIfNeeded();
  await page.screenshot({ path: path.join(SHOTS, "feat-expired.png") });
  console.log("expiry verdict OK");
}

await browser.close();
console.log("feature shots done");
