// Agent Passport demo — native WebAuthn, zero dependencies.

const SCOPES = ["read:calendar", "book:flights", "post:linkedin", "send:email"];
const state = { humanId: null, token: null, mandateId: null, grantedScope: [] };

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
function show(id, html) { const el = $(id); el.innerHTML = html; el.classList.add("show"); }
async function postJSON(url, body, headers = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { ok: res.ok, status: res.status, data: await res.json() };
}

// ---- scope checkboxes + action dropdown ----
const scopesEl = $("scopes");
SCOPES.forEach((s, i) => {
  const id = `sc-${i}`;
  const lab = document.createElement("label");
  lab.className = "chk";
  lab.innerHTML = `<input type="checkbox" id="${id}" value="${s}" ${i < 2 ? "checked" : ""}>${s}`;
  scopesEl.appendChild(lab);
});
const actionEl = $("action");
SCOPES.forEach((s) => {
  const o = document.createElement("option");
  o.value = s; o.textContent = s;
  actionEl.appendChild(o);
});

function selectedScopes() {
  return SCOPES.filter((_, i) => $(`sc-${i}`).checked);
}

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
        attestation: "none",
        timeout: 60000,
      },
    });
    const spki = cred.response.getPublicKey();
    const alg = cred.response.getPublicKeyAlgorithm();
    const { data } = await postJSON("/register", {
      credentialId: b64u.encode(cred.rawId),
      publicKey: b64u.encode(spki),
      alg,
    });
    state.humanId = data.humanId;
    show("out-register", `Passaporto creato.<br>human root: <b>${data.humanId}</b>`);
    $("btn-issue").disabled = false;
  } catch (e) {
    show("out-register", `<span class="pill bad">errore</span> ${e.message || e}`);
  }
});

// ---- Step 2: issue mandate (passkey signs) ----
$("btn-issue").addEventListener("click", async () => {
  try {
    const scope = selectedScopes();
    if (scope.length === 0) return show("out-issue", `<span class="pill bad">scegli almeno uno scope</span>`);
    const { data: ch } = await postJSON("/mandate/challenge", {
      humanId: state.humanId,
      agentName: $("agent-name").value || "Agent",
      scope,
      ttlSeconds: parseInt($("ttl").value, 10) || 300,
    });
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: b64u.decode(ch.challenge),
        rpId: "localhost",
        allowCredentials: [{ type: "public-key", id: b64u.decode(ch.credentialId) }],
        userVerification: "preferred",
        timeout: 60000,
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
    state.token = data.token;
    state.mandateId = ch.mandateId;
    state.grantedScope = scope;
    show("out-issue",
      `Mandato emesso e firmato con la passkey.<br>scope: <b>${scope.join(", ")}</b> · scade: <b>${ch.validUntil}</b><br>` +
      `token (VC-JWT): ${data.token.slice(0, 48)}…`);
    $("btn-act").disabled = false;
    $("btn-revoke").disabled = false;
  } catch (e) {
    show("out-issue", `<span class="pill bad">errore</span> ${e.message || e}`);
  }
});

// ---- Step 3: agent acts ----
function renderResult(id, res, status) {
  const c = res.checks || {};
  const order = ["issuerSignature", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];
  const items = order.map((k) => {
    if (!(k in c)) return `<li class="skip">○ ${k} <span class="muted">(non valutato)</span></li>`;
    return `<li class="${c[k] ? "y" : "n"}">${c[k] ? "✓" : "✗"} ${k}</li>`;
  }).join("");
  const ok = res.ok;
  show(id,
    `<p class="verdict ${ok ? "ok" : "bad"}">${ok ? "✓ AZIONE ESEGUITA" : `✗ RIFIUTATA (${status}) — ${res.reason}`}</p>` +
    (ok ? `<div>${res.message}</div>` : "") +
    `<ul class="checks">${items}</ul>`);
}

$("btn-act").addEventListener("click", async () => {
  try {
    const action = actionEl.value;
    const res = await fetch("/agent/act", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Mandate ${state.token}` },
      body: JSON.stringify({ action }),
    });
    const data = await res.json();
    renderResult("out-act", data, res.status);
    // On success the agent produced content + a signed receipt → prefill the verify box.
    if (data.ok && data.receipt) {
      $("rc-content").value = data.content;
      $("rc-receipt").value = data.receipt;
      $("btn-verify-content").disabled = false;
      show("out-verify", `<span class="pill ok">ricevuta pronta</span> premi "Verifica contenuto + ricevuta".`);
    }
  } catch (e) {
    show("out-act", `<span class="pill bad">errore</span> ${e.message || e}`);
  }
});

// ---- Step 4: verify content + receipt (consumer side) ----
const RECEIPT_ORDER = ["receiptSignature", "receiptClaims", "outputHash", "agentBinding",
  "issuerSignature", "trustedIssuer", "humanProof", "notExpired", "notRevoked", "scope"];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function renderReceiptVerdict(id, res) {
  const c = res.checks || {};
  const items = RECEIPT_ORDER.map((k) => {
    if (!(k in c)) return `<li class="skip">○ ${k} <span class="muted">(non valutato)</span></li>`;
    return `<li class="${c[k] ? "y" : "n"}">${c[k] ? "✓" : "✗"} ${k}</li>`;
  }).join("");
  show(id,
    `<p class="verdict ${res.valid ? "ok" : "bad"}">${res.valid ? "✓ CONTENUTO VALIDO" : `✗ NON VALIDO — ${esc(res.reason)}`}</p>` +
    `<div>${esc(res.summary)}</div>` +
    `<ul class="checks">${items}</ul>`);
}

$("btn-verify-content").addEventListener("click", async () => {
  try {
    const { data } = await postJSON("/verify-receipt", {
      content: $("rc-content").value,
      receipt: $("rc-receipt").value,
    });
    renderReceiptVerdict("out-verify", data);
  } catch (e) {
    show("out-verify", `<span class="pill bad">errore</span> ${e.message || e}`);
  }
});

// ---- Step 5: revoke ----
$("btn-revoke").addEventListener("click", async () => {
  const { data } = await postJSON("/revoke", { mandateId: state.mandateId });
  show("out-revoke", data.revoked
    ? `<span class="pill bad">REVOCATO</span> Ora ri-verifica il contenuto allo step 4 → la ricevuta è REVOCATA.`
    : `<span class="pill bad">errore</span> ${JSON.stringify(data)}`);
});
