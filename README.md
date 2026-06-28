# Agent Passport

**La patente d'identità per gli agenti AI.** Prova che dietro un bot c'è una **persona reale** che
l'ha autorizzato a fare una cosa precisa, per un tempo preciso — e che puoi **spegnere quando vuoi**.

![Demo: azione valida → revoca → rifiuto in tempo reale](docs/media/demo.gif)

*Stesso agente, stesso mandato. Prima della revoca: ✓ eseguito. Dopo: ✗ rifiutato all'istante.*

## Cos'è (in 2 righe)

Non chiediamo più "sei umano?" (gara persa: l'AI batte i CAPTCHA). Chiediamo **"hai il mandato di
una persona reale, ancora valido?"**. Un umano firma un **mandato** (con la sua passkey: impronta o
volto), l'agente lo porta, **chiunque** può verificarlo, e l'umano lo **revoca** quando vuole.

## Perché ora

- Oltre il **50% del traffico internet è bot** (2025); il traffico agentico cresce a tre cifre.
- a16z: *"il collo di bottiglia dell'economia degli agenti è l'identità, non l'intelligenza."*
- **EU AI Act Art. 50** (ago 2026) + norme IN/CA: serviranno prove machine-readable di chi ha
  autorizzato un'azione AI. Il bisogno sta arrivando per legge.

## Provalo in 3 comandi

```bash
cd packages/python && uv venv && uv pip install -e ".[server]"
cd ../../server && ../packages/python/.venv/bin/python run.py
# apri l'URL stampato (porta 8000 se libera, altrimenti la prima libera)
```

Crea il passaporto con la passkey → dai un incarico all'agente → l'agente agisce **solo se il
mandato è vivo** → premi **revoca** e viene rifiutato all'istante. C'è anche un verificatore
indipendente su `/verify.html`.

## I due pilastri

```
  PERSONA ──firma──►  MANDATO  ──portato da──►  AGENTE  ──produce──►  CONTENUTO + RICEVUTA
 (passkey)          cosa·quanto                 (DID)                       │
     ▲              ·revocabile                                             ▼
     └───────────────── REVOCA in tempo reale ──────────────────►  chiunque VERIFICA
```

1. **Agent Passport — il mandato.** *L'agente è autorizzato da un umano?* Patente firmata,
   con permessi (scope), scadenza, e revoca istantanea. *(la GIF sopra)*
2. **Content Receipt — lo scontrino.** *Questo output l'ha prodotto un agente autorizzato?* Una
   **ricevuta firmata** allegata all'output che lega `hash(contenuto) + agente + mandato + tempo`.
   Revoca il mandato → la ricevuta diventa **non valida all'istante**.

![Content Receipt: contenuto valido → revoca → contenuto revocato](docs/media/demo-receipt.gif)

## Cosa c'è nel repo

| | Dove | Verifica reale |
|--|--|--|
| 📐 Spec (mandato + Content Receipt §13 + Threat model) | [`SPEC.md`](SPEC.md) | — |
| 🐍 SDK Python | [`packages/python`](packages/python) | `pytest` · 22 test |
| 🟨 SDK JS (Node 20+ / browser) | [`packages/js`](packages/js) | `node --test` · 11 (verifica anche token+ricevuta da Python) |
| 🌐 Demo web (passkey, revoca live, ricevuta, `/verify.html`) | [`server`](server) | reale |
| 🤖 E2E (WebAuthn virtual authenticator) | [`e2e`](e2e) | `node run.mjs` · `node receipt.mjs` |
| 🚀 Integra in 5 minuti | [`QUICKSTART.md`](QUICKSTART.md) | — |

> Sotto il cofano: W3C **Verifiable Credentials 2.0** come VC-JWT, **Ed25519/`did:key`**, e
> **WebAuthn** usato come firma del mandato. Zero dipendenze esotiche, zero infra.

## Onestà brutale

Frontiera, scommessa su uno standard — non un incasso domani. **Non risolve la non-trasferibilità
del root**: un umano può prestare la sua passkey. Diamo *mandato + permessi + revoca*
(responsabilità), non la prova di essere un umano *unico*. Il Content Receipt non sopravvive
all'**analog hole** (rifotografi/riscrivi → firma persa) e non prova che il contenuto sia *vero*,
solo che è stato prodotto da un agente autorizzato. Revoca v1 = endpoint semplice (W3C Bitstring
Status List + ZK = fase 2, campi già predisposti). Valore iniziale = standard + reference impl +
posizionamento.

— Idea e architettura: [`CONCEPT.md`](CONCEPT.md) · ricerca: [`docs/RESEARCH.md`](docs/RESEARCH.md) ·
bozza post: [`docs/LINKEDIN.md`](docs/LINKEDIN.md)
