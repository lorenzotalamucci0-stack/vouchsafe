// Vouchsafe demo — native WebAuthn, zero dependencies. Plain-language, explain-everything UX.

const SCOPES = ["read:calendar", "book:flights", "post:linkedin", "send:email"];
const SCOPE_LABEL = {
  "read:calendar": "leggere il calendario",
  "book:flights": "prenotare voli",
  "post:linkedin": "pubblicare su LinkedIn",
  "send:email": "inviare email",
};
const state = { humanId: null, token: null, mandateId: null, history: [] };
const revokedIds = new Set();

// Plain-language names + one-line "why" for each verification check.
const CHECK_LABEL = {
  issuerSignature: "Emesso da Vouchsafe", recognizedFormat: "Formato riconosciuto",
  trustedIssuer: "Emittente riconosciuto",
  humanProof: "Autorizzato da una persona (passkey)", notExpired: "Mandato non scaduto",
  notRevoked: "Mandato non revocato", scope: "Azione tra i permessi",
  receiptSignature: "Ricevuta firmata dall'agente", receiptClaims: "Ricevuta coerente",
  outputHash: "Contenuto non modificato", agentBinding: "Agente collegato al mandato",
};
const CHECK_WHY = {
  issuerSignature: "Il mandato è firmato dal servizio Vouchsafe: non è un foglietto falso.",
  recognizedFormat: "Il mandato usa il formato Vouchsafe che il verificatore conosce.",
  trustedIssuer: "Viene proprio dall'emittente che ti aspetti, non da un impostore.",
  humanProof: "Dietro c'è un umano vero (ha firmato con la passkey), non un altro bot.",
  notExpired: "Il permesso non è ancora scaduto.",
  notRevoked: "Il permesso non è stato spento dalla persona.",
  scope: "L'azione richiesta è tra quelle permesse dal mandato.",
  receiptSignature: "Lo scontrino è firmato dall'agente: non è stato inventato.",
  receiptClaims: "I dati dentro lo scontrino sono coerenti tra loro.",
  outputHash: "Il contenuto è identico a quello firmato: nessuno l'ha modificato.",
  agentBinding: "Lo scontrino e il mandato parlano dello stesso agente.",
};
const REASON_LABEL = {
  noMandate: "nessun mandato presentato", issuerSignature: "firma non valida",
  trustedIssuer: "emittente non riconosciuto", humanProof: "manca la firma umana",
  notExpired: "mandato scaduto", notRevoked: "mandato revocato",
  scope: "azione fuori dai permessi", receiptSignature: "ricevuta manomessa",
  receiptClaims: "ricevuta incoerente", outputHash: "contenuto modificato",
  agentBinding: "agente non corrispondente",
};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let _uid = 0;
const uid = () => `u${++_uid}`;

const b64u = {
  encode(buf) { const b = new Uint8Array(buf); let s = ""; for (const x of b) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
  bytes(str) { str = str.replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "=";
    const bin = atob(str); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; },
  decode(str) { return b64u.bytes(str).buffer; },
};
const jwtPayload = (token) => { try { return JSON.parse(new TextDecoder().decode(b64u.bytes(token.split(".")[1]))); } catch { return null; } };
const scopeText = (arr) => (arr || []).map((s) => SCOPE_LABEL[s] || s).join(", ");

const $ = (id) => document.getElementById(id);
function show(id, html, kind) {
  const el = $(id); el.innerHTML = html; el.classList.remove("ok", "bad");
  if (kind) el.classList.add(kind); el.classList.add("show");
}
async function postJSON(url, body, headers = {}) {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  return { ok: res.ok, status: res.status, data: await res.json() };
}

// ---- "?" tooltips (toggle the element named by data-tip) + copy buttons ----
document.addEventListener("click", async (e) => {
  const q = e.target.closest(".q");
  if (q) { const t = document.getElementById(q.dataset.tip); if (t) t.hidden = !t.hidden; return; }
  const cp = e.target.closest(".copy");
  if (cp) { try { await navigator.clipboard.writeText(cp.dataset.copy); cp.textContent = "copiato ✓"; }
    catch { cp.textContent = "—"; } setTimeout(() => (cp.textContent = "copia"), 1400); return; }
  const rv = e.target.closest("[data-revoke]");
  if (rv) { await doRevoke(rv.dataset.revoke); return; }
  const rc = e.target.closest("[data-recheck]");
  if (rc) { await recheckChain(); }
});

// ---- "Come funziona" collapse (persisted) ----
const infoBody = $("info-body"), infoBtn = $("btn-info-toggle");
if (localStorage.getItem("ap_info_hidden") === "1") { infoBody.hidden = true; infoBtn.textContent = "mostra"; }
infoBtn.addEventListener("click", () => {
  infoBody.hidden = !infoBody.hidden;
  infoBtn.textContent = infoBody.hidden ? "mostra" : "nascondi";
  localStorage.setItem("ap_info_hidden", infoBody.hidden ? "1" : "0");
});

// ---- verdict + checks rendering ----
function verdictHead(ok, title, reason) {
  const tail = ok ? "" : (reason ? ` — ${esc(REASON_LABEL[reason] || reason)}` : "");
  return `<p class="verdict ${ok ? "ok" : "bad"}"><span class="ico">${ok ? "✓" : "✗"}</span><span>${esc(title)}${tail}</span></p>`;
}
function checksList(checks, order) {
  const rows = order.map((k) => {
    const label = CHECK_LABEL[k] || k;
    if (!(k in checks)) return `<li><div class="ck skip"><span class="mark">○</span><span>${esc(label)} <span class="note">(non valutato)</span></span></div></li>`;
    const wid = uid();
    const why = CHECK_WHY[k] ? `<button class="q" data-tip="${wid}">?</button>` : "";
    const whyP = CHECK_WHY[k] ? `<p class="why" id="${wid}" hidden>${esc(CHECK_WHY[k])}</p>` : "";
    return `<li><div class="ck ${checks[k] ? "y" : "n"}"><span class="mark">${checks[k] ? "✓" : "✗"}</span><span>${esc(label)}</span>${why}</div>${whyP}</li>`;
  }).join("");
  return `<ul class="checks">${rows}</ul>`;
}
function tokenRow(label, token) {
  const short = token.length > 26 ? `${token.slice(0, 20)}…${token.slice(-4)}` : token;
  return `<div class="tokrow">${esc(label)} <code>${esc(short)}</code><button class="copy" data-copy="${esc(token)}">copia</button></div>`;
}

// ---- decode a mandate token into readable fields ----
function decodeMandatePanel(token, mandateId) {
  const vc = jwtPayload(token)?.vc; if (!vc) return "";
  const s = vc.credentialSubject || {};
  const human = (s.authorizedBy?.humanId || "?");
  return `<details class="decode"><summary>Cosa c'è dentro questo mandato</summary><div class="kv">` +
    row("Agente", esc(s.agentName)) +
    row("Può", esc(scopeText(s.scope))) +
    row("Scade", `<span class="mstate" data-mid="${esc(mandateId)}" data-until="${esc(vc.validUntil)}"></span>`) +
    row("Autorizzato da", `<span title="${esc(human)}">${esc(human.slice(0, 42))}…</span> <span class="note">(pseudonimo: non rivela chi sei)</span>`) +
    `</div></details>`;
}
function decodeReceiptPanel(token) {
  const vc = jwtPayload(token)?.vc; if (!vc) return "";
  const s = vc.credentialSubject || {};
  return `<details class="decode"><summary>Cosa c'è dentro questa ricevuta</summary><div class="kv">` +
    row("Agente", esc(s.agentId?.slice(0, 42) + "…")) +
    row("Per il mandato", esc(s.mandateId)) +
    row("Permesso", esc(SCOPE_LABEL[s.scope] || s.scope)) +
    row("Impronta contenuto", `<span class="note">sha-256:</span> ${esc((s.output?.hash || "").slice(0, 24))}…`) +
    row("Prodotto il", esc(s.producedAt)) +
    `</div></details>`;
}
const row = (k, v) => `<div><span class="k">${k}</span><span class="v">${v}</span></div>`;

// ---- live status ticker (countdown + vivo/scaduto/revocato) ----
function refreshStates() {
  const now = Date.now();
  document.querySelectorAll(".mstate").forEach((el) => {
    const mid = el.dataset.mid, until = Date.parse(el.dataset.until);
    if (revokedIds.has(mid)) { el.innerHTML = `<span class="badge bad">Revocato</span>`; return; }
    const left = Math.round((until - now) / 1000);
    if (left <= 0) { el.innerHTML = `<span class="badge bad">Scaduto</span>`; return; }
    const m = Math.floor(left / 60), s = left % 60;
    el.innerHTML = `<span class="badge ok">Vivo</span> <span class="note">scade tra ${m}m ${String(s).padStart(2, "0")}s</span>`;
  });
}
setInterval(refreshStates, 1000);

// ---- session history ----
function renderHistory() {
  if (!state.history.length) return;
  $("history-sec").hidden = false;
  $("history").innerHTML = state.history.map((h) =>
    `<div class="hrow"><span class="hid">${esc(h.shortId)}</span>` +
    `<span class="hscope">${esc(scopeText(h.scope))}</span>` +
    `<span class="mstate" data-mid="${esc(h.mandateId)}" data-until="${esc(h.validUntil)}"></span>` +
    (revokedIds.has(h.mandateId) ? "" : `<button class="mini danger" data-revoke="${esc(h.mandateId)}">revoca</button>`) +
    `</div>`).join("");
  refreshStates();
}

async function doRevoke(mandateId) {
  const { data } = await postJSON("/revoke", { mandateId });
  if (data.revoked) { revokedIds.add(mandateId); renderHistory(); refreshStates();
    if (mandateId === state.mandateId)
      show("out-revoke", verdictHead(true, "Mandato revocato") +
        `<p class="saidline">Torna allo step 4 e ri-verifica lo stesso contenuto: ora risulta revocato.</p>`, "ok");
  }
}

// ---- build scope checkboxes + action dropdown ----
const scopesEl = $("scopes");
SCOPES.forEach((s, i) => {
  const lab = document.createElement("label"); lab.className = "chk";
  lab.innerHTML = `<input type="checkbox" id="sc-${i}" value="${s}" ${i < 2 ? "checked" : ""}>${SCOPE_LABEL[s]}`;
  scopesEl.appendChild(lab);
});
const actionEl = $("action");
SCOPES.forEach((s) => { const o = document.createElement("option"); o.value = s; o.textContent = `${SCOPE_LABEL[s]}  (${s})`; actionEl.appendChild(o); });
const selectedScopes = () => SCOPES.filter((_, i) => $(`sc-${i}`).checked);

// ---- Step 1: register passkey ----
$("btn-register").addEventListener("click", async () => {
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Vouchsafe", id: "localhost" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "demo-user", displayName: "Demo User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
        attestation: "none", timeout: 60000,
      },
    });
    const { data } = await postJSON("/register", {
      credentialId: b64u.encode(cred.rawId), publicKey: b64u.encode(cred.response.getPublicKey()),
      alg: cred.response.getPublicKeyAlgorithm(),
    });
    state.humanId = data.humanId;
    show("out-register", verdictHead(true, "Passaporto creato") +
      `<p class="saidline">Sei tu la radice di fiducia. Ora puoi dare un incarico a un agente.</p>`, "ok");
    $("btn-issue").disabled = false; $("lock-issue").hidden = true;
  } catch (e) { show("out-register", verdictHead(false, "Non riuscito") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad"); }
});

// ---- Step 2: issue mandate (passkey signs) ----
$("btn-issue").addEventListener("click", async () => {
  try {
    const scope = selectedScopes();
    if (!scope.length) return show("out-issue", verdictHead(false, "Scegli almeno un permesso"), "bad");
    const { data: ch } = await postJSON("/mandate/challenge", {
      humanId: state.humanId, agentName: $("agent-name").value || "Agent", scope,
      ttlSeconds: parseInt($("ttl").value, 10) || 300,
    });
    const a = await navigator.credentials.get({
      publicKey: {
        challenge: b64u.decode(ch.challenge), rpId: "localhost",
        allowCredentials: [{ type: "public-key", id: b64u.decode(ch.credentialId) }],
        userVerification: "preferred", timeout: 60000,
      },
    });
    const r = a.response;
    const { data } = await postJSON("/mandate/issue", {
      mandateId: ch.mandateId,
      assertion: { credentialId: b64u.encode(a.rawId), authenticatorData: b64u.encode(r.authenticatorData),
        clientDataJSON: b64u.encode(r.clientDataJSON), signature: b64u.encode(r.signature) },
    });
    state.token = data.token; state.mandateId = ch.mandateId;
    show("out-issue", verdictHead(true, "Mandato attivo") +
      `<p class="saidline">L'agente può: <b>${esc(scopeText(scope))}</b>.</p>` +
      decodeMandatePanel(data.token, ch.mandateId) +
      tokenRow("mandato (stringa firmata):", data.token), "ok");
    $("btn-act").disabled = false; $("btn-revoke").disabled = false; $("btn-delegate").disabled = false;
    for (const id of ["lock-act", "lock-revoke", "lock-delegate"]) $(id).hidden = true;
    state.history.push({ mandateId: ch.mandateId, shortId: ch.mandateId.split(":").pop().slice(0, 8), scope, validUntil: ch.validUntil });
    renderHistory();
  } catch (e) { show("out-issue", verdictHead(false, "Non riuscito") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad"); }
});

// ---- Step 3: agent acts ----
const MANDATE_ORDER = ["issuerSignature", "recognizedFormat", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];
$("btn-act").addEventListener("click", async () => {
  try {
    const action = actionEl.value;
    const res = await fetch("/agent/act", {
      method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Mandate ${state.token}` },
      body: JSON.stringify({ action }),
    });
    const data = await res.json(); const ok = !!data.ok;
    show("out-act", verdictHead(ok, ok ? "Azione eseguita" : "Azione rifiutata", data.reason) +
      (ok ? `<p class="saidline">${esc(data.message)}</p>` : "") +
      checksList(data.checks || {}, MANDATE_ORDER), ok ? "ok" : "bad");
    if (ok && data.receipt) {
      $("rc-content").value = data.content; $("rc-receipt").value = data.receipt;
      $("btn-verify-content").disabled = false; $("lock-verify").hidden = true;
      show("out-verify", verdictHead(true, "Ricevuta pronta") +
        `<p class="saidline">Premi "Verifica il contenuto" per controllarla.</p>`, "ok");
    }
  } catch (e) { show("out-act", verdictHead(false, "Errore") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad"); }
});

// ---- Step 4: verify content + receipt ----
const RECEIPT_ORDER = ["receiptSignature", "receiptClaims", "outputHash", "agentBinding",
  "issuerSignature", "recognizedFormat", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];
$("btn-verify-content").addEventListener("click", async () => {
  try {
    const { data } = await postJSON("/verify-receipt", { content: $("rc-content").value, receipt: $("rc-receipt").value });
    const decoded = $("rc-receipt").value ? decodeReceiptPanel($("rc-receipt").value) : "";
    show("out-verify", verdictHead(data.valid, data.valid ? "Contenuto valido" : "Contenuto non valido", data.reason) +
      (data.summary ? `<p class="saidline">${esc(data.summary)}</p>` : "") + decoded +
      checksList(data.checks || {}, RECEIPT_ORDER), data.valid ? "ok" : "bad");
  } catch (e) { show("out-verify", verdictHead(false, "Errore") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad"); }
});

// ---- Step 5: revoke ----
$("btn-revoke").addEventListener("click", () => doRevoke(state.mandateId));

// ---- Advanced: delegation chain ----
function renderChain(data) {
  const links = (data.links || []).map((l) =>
    `<li><div class="ck ${data.valid ? "y" : "n"}"><span class="mark">${l.kind === "root" ? "👤" : "🔗"}</span>` +
    `<span><b>${esc(l.agentName || (l.agent || "").slice(0, 22))}</b> — può: ${esc(scopeText(l.scope))} ` +
    `<span class="note">(${l.kind === "root" ? "radice umana" : "delegato"})</span></span></div></li>`).join("");
  show("out-delegate",
    verdictHead(data.valid, data.valid ? "Catena valida" : "Catena non valida", null) +
    `<p class="saidline">${esc(data.summary)}</p><ul class="checks">${links}</ul>` +
    `<button class="mini" data-recheck="1" style="margin-top:10px">↻ Ri-verifica la catena</button>`,
    data.valid ? "ok" : "bad");
}
async function recheckChain() {
  if (!state.childToken) return;
  const { data } = await postJSON("/verify-chain", { token: state.childToken, action: "book:flights" });
  renderChain(data);
}
$("btn-delegate").addEventListener("click", async () => {
  try {
    const { data: d } = await postJSON("/delegate", { parentToken: state.token, scope: ["book:flights"], ttlSeconds: 120 });
    if (d.error) return show("out-delegate", verdictHead(false, "Non riuscito") + `<p class="saidline">${esc(d.error)}</p>`, "bad");
    state.childToken = d.childToken;
    const vc = jwtPayload(d.childToken)?.vc;
    state.history.push({ mandateId: d.childId, shortId: d.childId.split(":").pop().slice(0, 8) + " · sub", scope: ["book:flights"], validUntil: vc.validUntil });
    renderHistory();
    await recheckChain();
  } catch (e) { show("out-delegate", verdictHead(false, "Errore") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad"); }
});

// ---- Reset ----
$("btn-reset").addEventListener("click", () => location.reload());
