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
| 📐 Spec (mandato + Content Receipt §13 + delega + Threat model) | [`SPEC.md`](SPEC.md) | — |
| 🐍 SDK Python | [`packages/python`](packages/python) | `pytest` · 32 test |
| 🟨 SDK JS (Node 20+ / browser) | [`packages/js`](packages/js) | `node --test` · 14 (verifica token+ricevuta+catena emessi da Python) |
| 🔗 Catena di delega (sub-mandati più stretti) | [`delegate.py`](packages/python/agent_passport/delegate.py) | nel suite sopra |
| 🌐 Demo web (passkey, revoca live, ricevuta, delega, `/verify.html`) | [`server`](server) | reale |
| 🤖 E2E (WebAuthn virtual authenticator) | [`e2e`](e2e) | `node run.mjs` · `receipt.mjs` · `chain.mjs` |
| 🚀 Integra in 5 minuti | [`QUICKSTART.md`](QUICKSTART.md) | — |

> Sotto il cofano: W3C **Verifiable Credentials 2.0** come VC-JWT, **Ed25519/`did:key`**, e
> **WebAuthn** usato come firma del mandato. Zero dipendenze esotiche, zero infra.

## Lavoro correlato & come differiamo

Onestà: **non ho inventato lo standard.** I grandi player stanno già standardizzando "mandato
agentico come Verifiable Credential". Agent Passport è una **reference implementation neutrale e
human-rooted, standalone/zero-infra**, che mette una **root umana (WebAuthn)** + uno **scontrino
vivente** sopra standard emergenti — non un nuovo root-of-trust.

| Progetto | Cosa fa | Come differiamo (onesto) |
|--|--|--|
| [Google **AP2**](https://github.com/google-agentic-commerce/AP2) (Agent Payments Protocol) | Mandato-come-VC, umano firma con passkey | AP2 è **payment-scoped**. Noi: scope **generico**, standalone, zero-infra, + **content receipt** (assente in AP2). |
| [**AIP**](https://arxiv.org/abs/2603.24775) (Agent Identity Protocol) | Delega verificabile, capability **attenuate**, catena, revoca | Il nostro data-model è ispirato ad AIP. **La catena di delega NON è nostra novità** (è il cuore di AIP/UCAN). Divergiamo su: **root umana WebAuthn** + **content receipt** (non specificati da AIP). |
| [**UCAN**](https://github.com/ucan-wg/spec) | Capability JWT delegabili/revocabili/attenuate | UCAN **non** ha root umana e la revoca è *eventually consistent*. Noi: **root umana WebAuthn** + revoca **real-time, fail-closed**. |
| [**C2PA** / Content Credentials](https://c2pa.org/) | Provenienza del contenuto (citato da EU AI Act Art. 50) | Il nostro Content Receipt **non lo rimpiazza**: aggiunge un binding **ortogonale** = *autorizzazione umana vivente e revocabile*, non solo "fatto da AI". Idealmente: receipt come **assertion dentro un manifest C2PA**. |
| [ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/) · [macaroons](https://research.google/pubs/pub41892/) · [biscuit](https://www.biscuitsec.org/) · [SPIFFE](https://spiffe.io/) | Capability/identità | **SPIFFE** = identità del *workload*; noi = mandato umano *on-behalf-of* (complementari). **macaroons**: il verifier ha il root-secret → **può forgiare**; noi chiave **pubblica** → chiunque verifica *senza* poter forgiare. ZCAP-LD/biscuit = capability affini, più pesanti o senza root umana. |

**La novità reale e stretta:** (a) **root umana WebAuthn** legata al *mandato esatto*; (b) **content
receipt** = autorizzazione *vivente* (cade con la revoca); (c) **revoca real-time fail-closed**. Tutto
il resto è costruito su standard esistenti — e lo dichiariamo.

## Onestà brutale

Frontiera, non un incasso domani. **Non risolve la non-trasferibilità del root**: un umano può
prestare la sua passkey. Diamo *mandato + permessi + revoca* (responsabilità), non la prova di
essere un umano *unico*. La passkey firma un **hash opaco**, non lo scope leggibile: il consenso
informato dipende dalla UI dell'issuer (vedi `SPEC.md` §Threat model — limite più serio, dichiarato).
Il Content Receipt non sopravvive all'**analog hole** e non prova che il contenuto sia *vero*, solo
che è stato prodotto da un agente autorizzato. Revoca v1 = endpoint semplice, **fail-closed** senza
grace (W3C Bitstring Status List + ZK = fase 2). **Posizionamento:** reference implementation
neutrale e human-rooted, mentre i grandi standardizzano la stessa cosa dentro i loro silos.

Licenza: **Apache-2.0** (vedi [`LICENSE`](LICENSE)) — adatta a uno standard/reference impl (patent grant).

— Idea e architettura: [`CONCEPT.md`](CONCEPT.md) · ricerca: [`docs/RESEARCH.md`](docs/RESEARCH.md) ·
bozza post: [`docs/LINKEDIN.md`](docs/LINKEDIN.md)
