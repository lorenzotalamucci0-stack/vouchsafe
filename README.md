# Agent Passport

**Una patente verificabile e revocabile per agenti AI.** Prova che un bot agisce per conto di un
umano reale autorizzato — con scope, scadenza e revoca. Non "sei umano?", ma "hai un mandato
umano valido?".

Un mandato porta **due firme**: la **passkey dell'umano** (WebAuthn — prova il mandato umano) e
l'**issuer** (Ed25519/`did:key`, VC-JWT). Un verifier controlla firma + scadenza + revoca + scope.
Allineato a [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/).

![Demo: mandato valido → revoca → rifiuto in tempo reale](docs/media/demo.gif)

*Stesso agente, stesso token. Prima della revoca: ✓ azione eseguita. Dopo: ✗ rifiutata in tempo reale.*

## I due pilastri

1. **Agent Passport (mandato)** — *l'agente è autorizzato da un umano?* La patente, sopra.
2. **Content Receipt (scontrino)** — *questo output l'ha prodotto un agente autorizzato?* Una
   **ricevuta firmata** allegata all'output, che lega `hash(output) + agent + mandato + scope + tempo`.
   Revocare il mandato invalida la ricevuta **in tempo reale**.

![Content Receipt: contenuto valido → revoca → contenuto revocato](docs/media/demo-receipt.gif)

*Stesso contenuto, stessa ricevuta. Revochi il mandato → la ricevuta passa da VALIDA a REVOCATA, senza ri-firmare nulla.*

## Cosa c'è qui

| | Dove | Verifica |
|--|--|--|
| 📐 Spec (mandato + Content Receipt §13 + Threat model) | [`SPEC.md`](SPEC.md) | — |
| 🐍 SDK Python (`issue`/`verify`/`revoke` + `sign_receipt`/`verify_receipt`) | [`packages/python`](packages/python) | `uv run pytest` (22 test) |
| 🟨 SDK JS (Node 20+ / browser) | [`packages/js`](packages/js) | `node --test` (11, verifica token + ricevuta da Python) |
| 🌐 Demo web (passkey, revoca live, ricevuta + `/verify.html`) | [`server`](server) | reale |
| 🤖 Test E2E (virtual authenticator) | [`e2e`](e2e) | `node run.mjs` · `node receipt.mjs` |
| 🚀 Integra in 5 minuti | [`QUICKSTART.md`](QUICKSTART.md) | — |

## Prova la demo (locale, zero costo)

```bash
# 1. SDK + server
cd packages/python && uv venv && uv pip install -e ".[server]"
# 2. avvia (sceglie la porta 8000 se libera, altrimenti la prima libera, e stampa l'URL)
cd ../../server && ../packages/python/.venv/bin/python run.py
# 3. apri l'URL stampato (es. http://localhost:8000)
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
