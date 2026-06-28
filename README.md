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
mandato è vivo** → premi **revoca** e viene rifiutato all'istante. Su `/verify.html` c'è un
**verificatore lato-utente**: la stessa logica `verify()` che chiunque può eseguire offline con
la sola chiave pubblica dell'issuer. *(Nota: in questa demo il controllo di revoca passa dallo
stesso processo del server — non è un secondo servizio indipendente; in produzione sarebbe una
fetch HTTP all'endpoint di status dell'issuer.)*

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
   La ricevuta certifica **autorizzazione al momento `producedAt`**, e la verifica riflette lo
   **stato corrente** del mandato: revochi → la ricevuta smette di verificare (è *autorizzazione
   vivente*, non un timbro d'archivio immutabile — distinzione in `SPEC.md` §13.4). Modello: non
   un nuovo standard di provenienza ma, idealmente, una **assertion proponibile dentro C2PA**.

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
| ⚙️ **Integrazione** (CLI, hook Claude Code, esempi) | [`INTEGRATION.md`](INTEGRATION.md) · [`integrations/`](integrations/) · [`examples/`](examples/) | `python examples/standalone.py` |
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
| [Google **AP2**](https://github.com/google-agentic-commerce/AP2) (Agent Payments Protocol) | Mandato-come-VC, umano firma con passkey, TTL+revoca; **Verifiable Intent** (log firmato delle azioni). **Donato a FIDO Alliance (apr 2026), 60+ org, governance aperta** | AP2 è *payment-agnostic* ma **mira al commerce agentico** (Intent/Cart/Payment mandate). AP è una **impl minimale standalone, scope `action:resource` libero**, eseguibile in locale. NON è "AP2 ridotto": è una reference impl neutrale, e dove possibile **interoperabile** (un mandato AP potrebbe diventare un'assertion AP2/Verifiable Intent). |
| [**AIP**](https://arxiv.org/abs/2603.24775) (Agent Identity Protocol) | Delega verificabile, capability **attenuate**, catena, revoca | Il nostro data-model è ispirato ad AIP. **La catena di delega NON è nostra novità** (è il cuore di AIP/UCAN). Divergiamo su: **root umana WebAuthn** + **content receipt** (non specificati da AIP). |
| [**UCAN**](https://github.com/ucan-wg/spec) | Capability JWT delegabili/revocabili/attenuate | UCAN **non** ha root umana ed è decentralizzato (revoca *eventually consistent* via gossip; il validator che apprende la revoca fallisce comunque chiuso). Noi: **root umana WebAuthn** + revoca via **endpoint centralizzato** — *scelta di deployment* (più immediata, meno decentralizzata), non un'invenzione. |
| [**C2PA** / Content Credentials](https://c2pa.org/) | Provenienza del contenuto (citato da EU AI Act Art. 50) | Il nostro Content Receipt **non lo rimpiazza**: aggiunge un binding **ortogonale** = *autorizzazione umana vivente e revocabile*, non solo "fatto da AI". Idealmente: receipt come **assertion dentro un manifest C2PA**. |
| [ZCAP-LD](https://w3c-ccg.github.io/zcap-spec/) · [macaroons](https://research.google/pubs/pub41892/) · [biscuit](https://www.biscuitsec.org/) · [SPIFFE](https://spiffe.io/) | Capability/identità | **SPIFFE** = identità del *workload*; noi = mandato umano *on-behalf-of* (complementari). **macaroons**: il verifier ha il root-secret → **può forgiare**; noi chiave **pubblica** → chiunque verifica *senza* poter forgiare. ZCAP-LD/biscuit = capability affini, più pesanti o senza root umana. |

**Cosa porta di proprio (onesto):** non primitivi crittografici nuovi — root umana, delega
attenuata, TTL, revoca sono **prior-art** (AP2/AIP/FIDO/UCAN). Il contributo è: (a) una
**reference implementation neutrale ed eseguibile in 3 comandi** (SDK Python+JS cross-verificati,
E2E con WebAuthn virtual-authenticator, Apache-2.0); (b) il **bridge end-to-end in un solo
artefatto provabile su laptop** — umano firma → agente produce → *chiunque verifica* → revoca
live — che nessuno dei singoli standard impacchetta così; (c) l'aggancio esplicito tra **mandato**
e **provenienza del contenuto** (content receipt). Il valore è l'integrazione e l'adozione, non un
nuovo standard.

## Onestà brutale

Frontiera, non un incasso domani. **Non risolve la non-trasferibilità del root**: un umano può
prestare la sua passkey. Diamo *mandato + permessi + revoca* (responsabilità), non la prova di
essere un umano *unico*. La passkey firma un **hash opaco**, non lo scope leggibile: il consenso
informato dipende dalla UI dell'issuer (vedi `SPEC.md` §Threat model — limite più serio, dichiarato).
Il Content Receipt non sopravvive all'**analog hole** e non prova che il contenuto sia *vero*, solo
che è stato prodotto da un agente autorizzato. Revoca v1 = endpoint semplice, **fail-closed** senza
grace (W3C Bitstring Status List + ZK = fase 2). **Posizionamento:** reference implementation
neutrale e human-rooted *complementare* agli standard in arrivo (AP2 è sotto **FIDO Alliance** in
governance aperta; AIP è un **IETF draft**) — non un concorrente né un "silo da scavalcare", ma
un'impl minimale, eseguibile e idealmente interoperabile.

Licenza: **Apache-2.0** (vedi [`LICENSE`](LICENSE)) — adatta a uno standard/reference impl (patent grant).

— Idea e architettura: [`CONCEPT.md`](CONCEPT.md) · ricerca: [`docs/RESEARCH.md`](docs/RESEARCH.md) ·
bozza post: [`docs/LINKEDIN.md`](docs/LINKEDIN.md)
