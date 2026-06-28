// Agent Passport demo — native WebAuthn, zero dependencies. Plain-language UX.

const SCOPES = ["read:calendar", "book:flights", "post:linkedin", "send:email"];
const SCOPE_LABEL = {
  "read:calendar": "leggere il calendario",
  "book:flights": "prenotare voli",
  "post:linkedin": "pubblicare su LinkedIn",
  "send:email": "inviare email",
};
const state = { humanId: null, token: null, mandateId: null };

// Plain-language names for the verification checks.
const CHECK_LABEL = {
  issuerSignature: "Emesso da Agent Passport",
  trustedIssuer: "Emittente riconosciuto",
  humanProof: "Autorizzato da una persona (passkey)",
  notExpired: "Mandato non scaduto",
  notRevoked: "Mandato non revocato",
  scope: "Azione tra i permessi",
  receiptSignature: "Ricevuta firmata dall'agente",
  receiptClaims: "Ricevuta coerente",
  outputHash: "Contenuto non modificato",
  agentBinding: "Agente collegato al mandato",
};
// Short reason shown in the headline when something fails.
const REASON_LABEL = {
  noMandate: "nessun mandato presentato",
  issuerSignature: "firma non valida",
  trustedIssuer: "emittente non riconosciuto",
  humanProof: "manca la firma umana",
  notExpired: "mandato scaduto",
  notRevoked: "mandato revocato",
  scope: "azione fuori dai permessi",
  receiptSignature: "ricevuta manomessa",
  receiptClaims: "ricevuta incoerente",
  outputHash: "contenuto modificato",
  agentBinding: "agente non corrispondente",
};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---- base64url <-> ArrayBuffer ----
const b64u = {
  encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  },
};

const $ = (id) => document.getElementById(id);
function show(id, html, kind) {
  const el = $(id);
  el.innerHTML = html;
  el.classList.remove("ok", "bad");
  if (kind) el.classList.add(kind);
  el.classList.add("show");
}
function verdictHead(ok, title, reason) {
  const ico = ok ? "✓" : "✗";
  const tail = ok ? "" : (reason ? ` — ${esc(REASON_LABEL[reason] || reason)}` : "");
  return `<p class="verdict ${ok ? "ok" : "bad"}"><span class="ico">${ico}</span><span>${esc(title)}${tail}</span></p>`;
}
function checksList(checks, order) {
  const items = order.map((k) => {
    const label = CHECK_LABEL[k] || k;
    if (!(k in checks)) return `<li class="skip"><span class="mark">○</span><span>${esc(label)} <span class="note">(non valutato)</span></span></li>`;
    return `<li class="${checks[k] ? "y" : "n"}"><span class="mark">${checks[k] ? "✓" : "✗"}</span><span>${esc(label)}</span></li>`;
  }).join("");
  return `<ul class="checks">${items}</ul>`;
}
function tokenRow(label, token) {
  const short = token.length > 28 ? `${token.slice(0, 22)}…${token.slice(-4)}` : token;
  return `<div class="tokrow">${esc(label)} <code>${esc(short)}</code>` +
    `<button class="copy" data-copy="${esc(token)}">copia</button></div>`;
}
async function postJSON(url, body, headers = {}) {
  const res = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body),
  });
  return { ok: res.ok, status: res.status, data: await res.json() };
}

// copy buttons (delegated)
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".copy");
  if (!btn) return;
  try { await navigator.clipboard.writeText(btn.dataset.copy); btn.textContent = "copiato ✓"; }
  catch { btn.textContent = "—"; }
  setTimeout(() => (btn.textContent = "copia"), 1400);
});

// ---- build scope checkboxes + action dropdown ----
const scopesEl = $("scopes");
SCOPES.forEach((s, i) => {
  const lab = document.createElement("label");
  lab.className = "chk";
  lab.innerHTML = `<input type="checkbox" id="sc-${i}" value="${s}" ${i < 2 ? "checked" : ""}>${SCOPE_LABEL[s]}`;
  scopesEl.appendChild(lab);
});
const actionEl = $("action");
SCOPES.forEach((s) => {
  const o = document.createElement("option");
  o.value = s; o.textContent = `${SCOPE_LABEL[s]}  (${s})`;
  actionEl.appendChild(o);
});
const selectedScopes = () => SCOPES.filter((_, i) => $(`sc-${i}`).checked);

// ---- Step 1: register passkey ----
$("btn-register").addEventListener("click", async () => {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "Agent Passport", id: "localhost" },
        user: { id: userId, name: "demo-user", displayName: "Demo User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
        attestation: "none", timeout: 60000,
      },
    });
    const { data } = await postJSON("/register", {
      credentialId: b64u.encode(cred.rawId),
      publicKey: b64u.encode(cred.response.getPublicKey()),
      alg: cred.response.getPublicKeyAlgorithm(),
    });
    state.humanId = data.humanId;
    show("out-register", verdictHead(true, "Passaporto creato") +
      `<p class="saidline">Sei tu la radice di fiducia. Ora puoi dare un incarico a un agente.</p>`, "ok");
    $("btn-issue").disabled = false;
  } catch (e) {
    show("out-register", verdictHead(false, "Non riuscito") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad");
  }
});

// ---- Step 2: issue mandate (passkey signs) ----
$("btn-issue").addEventListener("click", async () => {
  try {
    const scope = selectedScopes();
    if (!scope.length) return show("out-issue", verdictHead(false, "Scegli almeno un permesso"), "bad");
    const { data: ch } = await postJSON("/mandate/challenge", {
      humanId: state.humanId,
      agentName: $("agent-name").value || "Agent",
      scope,
      ttlSeconds: parseInt($("ttl").value, 10) || 300,
    });
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: b64u.decode(ch.challenge), rpId: "localhost",
        allowCredentials: [{ type: "public-key", id: b64u.decode(ch.credentialId) }],
        userVerification: "preferred", timeout: 60000,
      },
    });
    const r = assertion.response;
    const { data } = await postJSON("/mandate/issue", {
      mandateId: ch.mandateId,
      assertion: {
        credentialId: b64u.encode(assertion.rawId),
        authenticatorData: b64u.encode(r.authenticatorData),
        clientDataJSON: b64u.encode(r.clientDataJSON),
        signature: b64u.encode(r.signature),
      },
    });
    state.token = data.token; state.mandateId = ch.mandateId;
    const human = scope.map((s) => SCOPE_LABEL[s]).join(", ");
    show("out-issue", verdictHead(true, "Mandato attivo") +
      `<p class="saidline">L'agente può: <b>${esc(human)}</b>. Scade alle <b>${esc(ch.validUntil)}</b>.</p>` +
      tokenRow("mandato:", data.token), "ok");
    $("btn-act").disabled = false; $("btn-revoke").disabled = false;
  } catch (e) {
    show("out-issue", verdictHead(false, "Non riuscito") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad");
  }
});

// ---- Step 3: agent acts ----
const MANDATE_ORDER = ["issuerSignature", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];

$("btn-act").addEventListener("click", async () => {
  try {
    const action = actionEl.value;
    const res = await fetch("/agent/act", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Mandate ${state.token}` },
      body: JSON.stringify({ action }),
    });
    const data = await res.json();
    const ok = !!data.ok;
    show("out-act",
      verdictHead(ok, ok ? "Azione eseguita" : "Azione rifiutata", data.reason) +
      (ok ? `<p class="saidline">${esc(data.message)}</p>` : "") +
      checksList(data.checks || {}, MANDATE_ORDER), ok ? "ok" : "bad");
    if (ok && data.receipt) {
      $("rc-content").value = data.content;
      $("rc-receipt").value = data.receipt;
      $("btn-verify-content").disabled = false;
      show("out-verify", verdictHead(true, "Ricevuta pronta") +
        `<p class="saidline">Premi "Verifica il contenuto" per controllarla.</p>`, "ok");
    }
  } catch (e) {
    show("out-act", verdictHead(false, "Errore") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad");
  }
});

// ---- Step 4: verify content + receipt (consumer side) ----
const RECEIPT_ORDER = ["receiptSignature", "receiptClaims", "outputHash", "agentBinding",
  "issuerSignature", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];

$("btn-verify-content").addEventListener("click", async () => {
  try {
    const { data } = await postJSON("/verify-receipt", {
      content: $("rc-content").value, receipt: $("rc-receipt").value,
    });
    show("out-verify",
      verdictHead(data.valid, data.valid ? "Contenuto valido" : "Contenuto non valido", data.reason) +
      (data.summary ? `<p class="saidline">${esc(data.summary)}</p>` : "") +
      checksList(data.checks || {}, RECEIPT_ORDER), data.valid ? "ok" : "bad");
  } catch (e) {
    show("out-verify", verdictHead(false, "Errore") + `<p class="saidline">${esc(e.message || e)}</p>`, "bad");
  }
});

// ---- Step 5: revoke ----
$("btn-revoke").addEventListener("click", async () => {
  const { data } = await postJSON("/revoke", { mandateId: state.mandateId });
  show("out-revoke", data.revoked
    ? verdictHead(true, "Mandato revocato") +
      `<p class="saidline">Torna allo step 4 e ri-verifica lo stesso contenuto: ora risulta revocato.</p>`
    : verdictHead(false, "Errore") + `<p class="saidline">${esc(JSON.stringify(data))}</p>`,
    data.revoked ? "ok" : "bad");
});

// ---- Reset ----
$("btn-reset").addEventListener("click", () => location.reload());
