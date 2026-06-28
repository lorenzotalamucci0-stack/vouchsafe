# Agent Passport — Concept / PRD

**Una patente verificabile e revocabile per agenti AI.**
*Prova che un bot agisce per conto di un umano reale autorizzato — scope, scadenza, revoca.*

---

## 1. Il problema (perché esiste)

Gli agenti AI stanno invadendo internet: navigano, comprano, postano, parlano con altri agenti.
Oggi, davanti a un'azione fatta da un bot, **non esiste un modo standard per rispondere a:**

- chi c'è dietro questo agente?
- una persona reale l'ha autorizzato a fare *questa* cosa?
- fino a quando? entro quali limiti?
- l'autorizzazione è **ancora valida**, o è stata revocata?

Il web risponde a "sei umano?" con i CAPTCHA — una corsa **persa** (l'AI li risolve). E "provare
che sei un umano unico" è un muro: un umano vero può **affittare** la propria identità a un bot
(nessuna crittografia lo impedisce — è economia). Quel problema lo lasciamo a chi ha scala (World).

**La domanda giusta non è "sei umano?" ma "hai un mandato umano valido?".**

## 2. Perché ora (il timing)

- **>50% del traffico internet è bot** (2025). Traffico **agentico +450%** in un anno.
- **a16z**: *"il collo di bottiglia dell'economia degli agenti ora è l'identità, non l'intelligenza."*
- Il position paper **OpenAI/MIT/Microsoft/Harvard** ("Personhood Credentials", arXiv 2408.07892,
  32 autori) segna esplicitamente come **mancante**: *norme e standard per gli agenti AI*.
- **MCP** e **A2A** (protocolli agente↔tool e agente↔agente) fanno esplodere il numero di agenti
  → ognuno avrà bisogno di una credenziale/mandato verificabile per essere accettato.

Finestra: nascente ma **non vergine** — Google AP2, AIP, UCAN stanno già standardizzando "mandato
agentico come VC" (AP2 con 60+ partner). I primitivi crittografici sono maturi solo da poco
(post-2022). Posizione onesta: **non inventiamo lo standard, ne facciamo una reference
implementation neutrale e human-rooted** — root umana WebAuthn + scontrino vivente + revoca
real-time, standalone e zero-infra, mentre i grandi standardizzano la stessa cosa dentro i loro silos.

## 3. La soluzione (il meccanismo)

Un **mandato delegato** (delegated capability), firmato da un umano verificato, portato
dall'agente, controllabile da chiunque, revocabile in qualsiasi momento.

```
[Umano verificato] --firma--> [Mandato] --portato da--> [Agente AI] --presenta a--> [Verifier]
   (root: passkey/                {agent_id, scope,                         controlla:
    WebAuthn, o World ID,          expiry, nullifier,                       firma valida?
    o VC di terzi)                 revoca-URL, firma}                       non scaduto?
                                                                           non revocato?
                                          ^                                 scope ok?
                                          |
                                   [Revoca] <-- l'umano spegne il mandato quando vuole
```

**I pezzi (tutti su standard esistenti, niente da inventare da zero):**
1. **Root of personhood** = NON lo costruiamo. L'umano si verifica con quello che ha già:
   passkey/WebAuthn (Secure Enclave), oppure World ID, oppure una Verifiable Credential.
   *Pluralistico*: l'utente sceglie il root, noi non siamo l'autorità.
2. **Mandato** = una Verifiable Credential firmata: `{agent_id, human_root (pseudonimo),
   scope, expiry, nullifier, revocation_endpoint, signature}`.
3. **Binding all'hardware** (opzionale) = WebAuthn attestation → la chiave vive in un enclave non
   esportabile: alza il costo di vendere/clonare il mandato.
4. **Revoca** = status list / endpoint: l'umano uccide il mandato → l'agente smette di essere
   accettato. **Questo è il cuore del valore**: accountability, non identità.
5. **Privacy (opzionale, ZK)** = provare "questo agente ha un mandato umano valido" **senza
   rivelare CHI** è l'umano (BBS+ / nullifier / Semaphore).

## 4. Cosa rende difendibile per un team piccolo

- È un **layer applicativo**, non un root-of-trust → **non serve scala** né istituzioni (a
  differenza di World/Worldcoin). Lo costruisci in **settimane**, non anni.
- Il valore è la **reference implementation neutrale + l'SDK + la root umana/scontrino sopra
  standard emergenti**, non una rete biometrica né un nuovo standard da zero.
- Si aggancia a tutto ciò su cui Pampa già lavora (agenti, Leev): un agente di Leev potrebbe
  **portare un mandato firmato** quando agisce per un cliente.

## 5. Prototipo minimo (MVP, settimane)

1. **SDK/lib** (`issue`, `present`, `verify`, `revoke`):
   - un umano firma un mandato con la sua passkey → token;
   - un agente lo presenta;
   - un verifier valida firma + scadenza + revoca + scope.
2. **Demo end-to-end**: un agente posta/agisce **solo se** ha un mandato vivo; premi "revoca" →
   l'agente viene rifiutato in tempo reale. *Questo screenshot/video È il post LinkedIn.*
3. **Bozza di spec** del formato mandato (allineata a W3C Verifiable Credentials), pubblicabile.

Stack candidato (economico): WebAuthn/passkey (zero costo, nativo browser) + un backend minimo
(FastAPI) + status list per revoca. ZK come fase 2.

## 6. Onestà brutale (i rischi — da NON nascondere, anche nel post)

- **È una scommessa su uno standard.** Gli standard sono difficili: un big player (Anthropic,
  Google con A2A, OpenAI) potrebbe definirne uno proprio e oscurarci. Vinciamo solo se siamo
  primi, neutrali e adottati.
- **Domanda nascente** = potrebbe essere troppo presto di 6-12 mesi.
- **Non risolve la non-trasferibilità al root**: un umano può comunque prestare la sua passkey.
  Noi diamo *mandato + scope + revoca* (responsabilità), non la prova di unicità.
- **Non è vendibile domani.** Valore iniziale = visibilità/thought-leadership + (poi) SDK/SaaS.

## 7. Modello di valore (oltre la visibilità)
- v0: standard aperto + reference impl (OSS) → reputazione, community, posizionamento.
- v1: SDK + "verify-as-a-service" (endpoint hosted di verifica/revoca) a consumo.
- v1+: dashboard per chi gestisce flotte di agenti (lega ai mandati) — qui tocca Leev.

## 8. Prossimi passi (per la nuova chat)
1. Plan Mode: architettura prototipo + scelta primitivi.
2. Costruire l'MVP (issue/present/verify/revoke + demo).
3. Scrivere la mini-spec del formato mandato.
4. Registrare la demo → post LinkedIn (bozza già in `docs/LINKEDIN.md`).

Fonti complete in `docs/RESEARCH.md`.
