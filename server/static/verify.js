// Standalone consumer widget: paste content + receipt -> plain-language verdict.

const ORDER = ["receiptSignature", "receiptClaims", "outputHash", "agentBinding",
  "issuerSignature", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];

const $ = (id) => document.getElementById(id);
// Escape any server-returned field before putting it in innerHTML (fields can come from an
// attacker-signed-but-invalid receipt).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

$("btn").addEventListener("click", async () => {
  const out = $("out");
  out.classList.add("show");
  out.innerHTML = "Verifico…";
  try {
    const res = await fetch("/verify-receipt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: $("content").value, receipt: $("receipt").value }),
    });
    const r = await res.json();
    const c = r.checks || {};
    const items = ORDER.map((k) =>
      k in c
        ? `<li class="${c[k] ? "y" : "n"}">${c[k] ? "✓" : "✗"} ${k}</li>`
        : `<li class="skip">○ ${k} <span style="opacity:.6">(non valutato)</span></li>`
    ).join("");
    out.innerHTML =
      `<p class="verdict ${r.valid ? "ok" : "bad"}">${r.valid ? "✓ VALIDO" : `✗ NON VALIDO — ${esc(r.reason)}`}</p>` +
      `<div>${esc(r.summary)}</div>` +
      (r.agentId ? `<div class="meta">agente: ${esc(r.agentId)}<br>umano (pseudonimo): ${esc(r.humanId || "?")}<br>scope: ${esc(r.scope || "?")} · prodotto: ${esc(r.producedAt || "?")}</div>` : "") +
      `<ul class="checks">${items}</ul>`;
  } catch (e) {
    out.innerHTML = `<p class="verdict bad">errore</p><div>${e.message || e}</div>`;
  }
});
