# Agent Passport

**Una patente verificabile e revocabile per agenti AI.** Prova che un bot agisce per conto di un
umano reale autorizzato — con scope, scadenza e revoca. Non "sei umano?", ma "hai un mandato
umano valido?".

Un mandato porta **due firme**: la **passkey dell'umano** (WebAuthn — prova il mandato umano) e
l'**issuer** (Ed25519/`did:key`, VC-JWT). Un verifier controlla firma + scadenza + revoca + scope.
Allineato a [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/).

## Cosa c'è qui (v1)

| | Dove | Verifica |
|--|--|--|
| 📐 Spec del formato | [`SPEC.md`](SPEC.md) | — |
| 🐍 SDK Python (`issue`/`present`/`verify`/`revoke`) | [`packages/python`](packages/python) | `uv run pytest` (8 test) |
| 🟨 SDK JS (Node 20+ / browser) | [`packages/js`](packages/js) | `node --test` (verifica un token emesso da Python) |
| 🌐 Demo web end-to-end | [`server`](server) | passkey reale, revoca in tempo reale |
| 🤖 Test E2E (virtual authenticator) | [`e2e`](e2e) | `node run.mjs` |
| 🚀 Integra in 5 minuti | [`QUICKSTART.md`](QUICKSTART.md) | — |

## Prova la demo (locale, zero costo)

```bash
# 1. SDK + server
cd packages/python && uv venv && uv pip install -e ".[server]"
# 2. avvia
cd ../../server && AP_BASE_URL=http://localhost:8000 \
  ../packages/python/.venv/bin/python -m uvicorn app:app --port 8000
# 3. apri http://localhost:8000
```

Crei un passaporto con la passkey → generi un mandato (scope + scadenza) per un agente →
l'agente esegue un'azione sull'endpoint protetto **solo se il mandato è vivo** → premi **revoca**
e l'agente viene rifiutato all'istante.

## Contesto

- 📄 Idea, architettura, rischi → [`CONCEPT.md`](CONCEPT.md)
- 🔬 Ricerca & fonti → [`docs/RESEARCH.md`](docs/RESEARCH.md)
- 📣 Bozza post LinkedIn → [`docs/LINKEDIN.md`](docs/LINKEDIN.md)

## Onestà brutale

Frontiera, scommessa su uno standard. **Non risolve la non-trasferibilità del root** (un umano
può prestare la sua passkey): diamo *mandato + scope + revoca* (responsabilità), non prova di
unicità. Revoca v1 = endpoint semplice; W3C Bitstring Status List e ZK selective-disclosure sono
fase 2 (campi già predisposti). Non vendibile domani — valore iniziale = standard + reference
impl + posizionamento.
