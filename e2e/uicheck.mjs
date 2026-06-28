// UI QA: zero console errors + zero horizontal overflow, on / and /verify.html, at mobile+desktop.
import { chromium } from "playwright";

const BASE = process.env.AP_BASE_URL || "http://localhost:8090";
const browser = await chromium.launch();
let failures = 0;
const check = (n, c) => { console.log(`${c ? "✓" : "✗"} ${n}`); if (!c) failures++; };

for (const pagePath of ["/", "/verify.html"]) {
  for (const vp of [{ w: 380, h: 780, name: "mobile" }, { w: 1100, h: 820, name: "desktop" }]) {
    const ctx = await browser.newContext({ viewport: { width: vp.w, height: vp.h } });
    const page = await ctx.newPage();
    const errors = [];
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.goto(BASE + pagePath, { waitUntil: "networkidle" });
    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check(`${pagePath} @${vp.name}: no console errors`, errors.length === 0);
    if (errors.length) console.log("    ", errors.slice(0, 3));
    check(`${pagePath} @${vp.name}: no horizontal overflow (Δ=${overflow})`, overflow <= 0);
    await ctx.close();
  }
}
await browser.close();
console.log(failures === 0 ? "\nUI QA PASSED" : `\n${failures} UI QA FAIL`);
process.exit(failures === 0 ? 0 : 1);
