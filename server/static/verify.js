// Standalone consumer widget: paste content + receipt -> plain-language verdict.

const ORDER = ["receiptSignature", "receiptClaims", "outputHash", "agentBinding",
  "issuerSignature", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];
const CHECK_LABEL = {
  receiptSignature: "Ricevuta firmata dall'agente",
  receiptClaims: "Ricevuta coerente",
  outputHash: "Contenuto non modificato",
  agentBinding: "Agente collegato al mandato",
  issuerSignature: "Mandato emesso da Agent Passport",
  trustedIssuer: "Emittente riconosciuto",
  humanProof: "Autorizzato da una persona (passkey)",
  notExpired: "Mandato non scaduto",
  notRevoked: "Mandato non revocato",
  scope: "Azione tra i permessi",
};

const $ = (id) => document.getElementById(id);
// Escape any server-returned field before putting it in innerHTML (fields can come from an
// attacker-signed-but-invalid receipt).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

$("btn").addEventListener("click", async () => {
  const out = $("out");
  out.className = "out show";
  out.innerHTML = "Verifico…";
  try {
    const res = await fetch("/verify-receipt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: $("content").value, receipt: $("receipt").value }),
    });
    const r = await res.json();
    const c = r.checks || {};
    const items = ORDER.map((k) => {
      const label = CHECK_LABEL[k] || k;
      return k in c
        ? `<li class="${c[k] ? "y" : "n"}"><span class="mark">${c[k] ? "✓" : "✗"}</span><span>${esc(label)}</span></li>`
        : `<li class="skip"><span class="mark">○</span><span>${esc(label)} (non valutato)</span></li>`;
    }).join("");
    out.className = `out show ${r.valid ? "ok" : "bad"}`;
    out.innerHTML =
      `<p class="verdict ${r.valid ? "ok" : "bad"}"><span class="ico">${r.valid ? "✓" : "✗"}</span>` +
      `<span>${r.valid ? "Ricevuta autentica" : "Ricevuta NON valida"}</span></p>` +
      `<p class="saidline">${esc(r.summary)}</p>` +
      (r.agentId ? `<div class="meta">agente: ${esc(r.agentId)}<br>persona (pseudonimo): ${esc(r.humanId || "?")}<br>permesso: ${esc(r.scope || "?")} · prodotto: ${esc(r.producedAt || "?")}</div>` : "") +
      `<ul class="checks">${items}</ul>`;
  } catch (e) {
    out.className = "out show bad";
    out.innerHTML = `<p class="verdict bad"><span class="ico">✗</span><span>Errore</span></p><p class="saidline">${esc(e.message || e)}</p>`;
  }
});
