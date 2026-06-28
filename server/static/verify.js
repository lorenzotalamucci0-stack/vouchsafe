// Standalone consumer widget: paste content + receipt -> plain-language verdict.

const ORDER = ["receiptSignature", "receiptClaims", "outputHash", "agentBinding",
  "issuerSignature", "recognizedFormat", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];
const CHECK_LABEL = {
  receiptSignature: "Ricevuta firmata dall'agente",
  receiptClaims: "Ricevuta coerente",
  outputHash: "Contenuto non modificato",
  agentBinding: "Agente collegato al mandato",
  issuerSignature: "Mandato emesso da Agent Passport",
  recognizedFormat: "Formato riconosciuto",
  trustedIssuer: "Emittente riconosciuto",
  humanProof: "Autorizzato da una persona (passkey)",
  notExpired: "Mandato non scaduto",
  notRevoked: "Mandato non revocato",
  scope: "Azione tra i permessi",
};
const CHECK_WHY = {
  receiptSignature: "Lo scontrino è firmato dall'agente: non è stato inventato.",
  receiptClaims: "I dati dentro lo scontrino sono coerenti tra loro.",
  outputHash: "Il contenuto è identico a quello firmato: nessuno l'ha modificato.",
  agentBinding: "Lo scontrino e il mandato parlano dello stesso agente.",
  issuerSignature: "Il mandato è firmato dal servizio Agent Passport.",
  recognizedFormat: "Il mandato usa un formato che il verificatore conosce.",
  trustedIssuer: "Viene proprio dall'emittente che ti aspetti.",
  humanProof: "Dietro c'è un umano vero (ha firmato con la passkey).",
  notExpired: "Il permesso non è ancora scaduto.",
  notRevoked: "Il permesso non è stato spento dalla persona.",
  scope: "L'azione era tra quelle permesse dal mandato.",
};

const $ = (id) => document.getElementById(id);
// Escape any server-returned field before putting it in innerHTML (fields can come from an
// attacker-signed-but-invalid receipt).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let _uid = 0;
// "?" tooltips toggle the element named by data-tip.
document.addEventListener("click", (e) => {
  const q = e.target.closest(".q"); if (!q) return;
  const t = document.getElementById(q.dataset.tip); if (t) t.hidden = !t.hidden;
});

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
      if (!(k in c)) return `<li class="skip"><span class="mark">○</span><span>${esc(label)} (non valutato)</span></li>`;
      const wid = `w${++_uid}`;
      const q = CHECK_WHY[k] ? ` <button class="q" data-tip="${wid}">?</button>` : "";
      const why = CHECK_WHY[k] ? `<p class="why" id="${wid}" hidden>${esc(CHECK_WHY[k])}</p>` : "";
      return `<li class="${c[k] ? "y" : "n"}"><span class="mark">${c[k] ? "✓" : "✗"}</span><span>${esc(label)}</span>${q}</li>${why}`;
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
