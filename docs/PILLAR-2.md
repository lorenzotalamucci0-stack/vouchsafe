# Pilastro 2 — Agent-Attributed Content Provenance (la "ricevuta del contenuto")

> Estensione di Vouchsafe. **NON è un progetto nuovo, NON va costruito ora.** È la **FASE
> SUCCESSIVA**: si fa DOPO che il Pilastro 1 (il mandato) funziona, perché riusa la stessa
> identica infrastruttura (W3C Verifiable Credentials + DID). Emerso dal deep-dive del 28 giu 2026.

## I due pilastri (la visione)
- **Pilastro 1 — Vouchsafe**: *questo agente è autorizzato da un umano?* (il mandato firmato,
  revocabile, con scope + scadenza).
- **Pilastro 2 — Content Receipt**: *questo contenuto/azione l'ha prodotto un agente autorizzato?*
  Una "ricevuta" firmata allegata all'output dell'agente.

Insieme = **l'infrastruttura di fiducia dell'internet degli agenti.**

## Cos'è il Pilastro 2 (in una riga)
Una **ricevuta firmata** che lega: `output-hash + agent DID + mandate-id + scope + timestamp`,
verificabile da chiunque → risponde a *"quale agente ha prodotto questo, sotto quale mandato umano,
entro quale scope, ed era autorizzato?"*

## Perché NON è "autenticità dei contenuti generica" (che è chiusa)
- **NON** rilevare AI (causa persa dimostrata: Sadasivan, watermark forte impossibile).
- **NON** sfidare C2PA sul firmare (di Adobe/MS/Google/OpenAI/Cloudflare = suicidio).
- **NON** "il consumatore verifica se una foto è vera" (OpenOrigins $24M + OpenAI già lì → muori).
- **SÌ** solo l'asse scoperto: *provenienza dell'output agentico legata al mandato umano*. C2PA dice
  "quale MODELLO ha generato", non "quale AGENTE autorizzato da chi". Google AP2 firma le
  TRANSAZIONI, non l'output. Nessuno ha fatto il ponte sul contenuto.

## Perché è reale
- **Legge che lo impone**: EU AI Act **Art. 50 (ago 2026)** + India IT Rules 2026 + California SB942
  → disclosure machine-readable dei contenuti AI. Un agente che pubblica in UE dovrà provare
  disclosure + mandato → **domanda forzata**.
- **Campo vuoto ma validato**: l'unico tentativo affine (Vouchsafe System / APS) ha 33★ ed è
  stato rifiutato → idea regge, nessuno l'ha occupata.
- **Riuso**: stesso VC/DID del Pilastro 1, formato allineato a Google AP2 (interoperi, non competi).
  Sforzo = MEDIO.

## Cosa aggiunge (il delta tecnico, quando ci arrivi)
1. **Schema** del content-receipt VC (output-hash + agent DID + mandate-id + scope + timestamp).
2. **Binding** output→receipt (perceptual hash robusto per sopravvivere a re-encoding; hard hash
   per integrità).
3. **Verifier SDK/widget** consumer-side: incolli l'URL/file → "prodotto da agente X, mandato di
   umano Y (pseudonimo), scope Z, valido/revocato".

## Onestà (limiti reali — non nasconderli)
- Vive **solo agganciato al Pilastro 1**. Da solo non è difendibile.
- **Analog hole** irrisolto (rifotografi lo schermo → firma persa). Limite di categoria, non del design.
- **Adozione** è la guerra vera (stesso problema che frena C2PA). Mitigare restando agganciati al
  mandato + cavalcando l'obbligo EU AI Act.
- Scommessa su uno standard, non incasso domani (come il Pilastro 1).

## Quando / come integrarlo
- **Trigger**: quando il Pilastro 1 (issue/present/verify/revoke + demo) funziona.
- **Nella build chat**, allora: *"Pilastro 1 ok. Ora la fase 2: leggi docs/PILLAR-2.md, Plan Mode."*
- È additivo: nuovo schema VC + nuovo verifier sopra l'infra esistente. Niente da rifare.
