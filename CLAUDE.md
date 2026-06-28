# CLAUDE.md — Vouchsafe (Know-Your-Agent)

> Progetto di Pampa. Nato dalla sessione di brainstorming del 28 giu 2026 (deep-research su
> proof-of-personhood → la crepa vera non è "provare un umano" ma **provare il mandato umano di
> un agente AI**). Frontiera, non SaaS pulito: scommessa su uno standard + visibilità (LinkedIn).

## Cos'è (in una riga)
Un **passaporto/patente verificabile e revocabile per agenti AI**: prova che un agente sta
agendo per conto di un **umano reale autorizzato**, con uno **scope** preciso e una **scadenza**,
e che il permesso è **ancora valido** (revocabile in qualsiasi momento).

## Cosa NON è (per non sbagliare direzione)
- NON è "provare che sei umano" (proof-of-personhood) → muro irrisolvibile (un umano può
  affittarsi a un bot) o già vinto da World su scala. Lo **eredito**, non lo reinvento.
- NON è una nuova biometria, NON è un token/blockchain, NON è un nuovo root-of-trust.
- È un **layer sottile** sopra login esistenti (passkey/WebAuthn, o World ID, o VC di terzi).

## Perché ora
- Internet >50% bot (2025); traffico agentico +450%.
- a16z: "il collo di bottiglia dell'economia degli agenti ora è l'**identità**, non l'intelligenza".
- Paper OpenAI/MIT (arXiv 2408.07892) segna come **assente**: "norme e standard per agenti AI".
- MCP/A2A fanno proliferare gli agenti → serviranno credenziali/mandati verificabili.

## Stato
- 28 giu 2026: scaffold + concept. **Nessun codice ancora.** Prossimo passo = prototipo minimo.
- Vedi `CONCEPT.md` (idea completa + architettura + rischi) e `docs/RESEARCH.md` (fonti).
- `docs/LINKEDIN.md` = bozza post per visibilità (Pampa condivide domani).

## Regole di lavoro (VibeOS Pampa)
- Italiano sempre. Onestà brutale (è una scommessa, non una rendita: dirlo).
- Plan Mode prima di Build. Tag rollback prima di operazioni distruttive.
- Costi: tutto locale finché non serve infra; allora stack più economico (skill infra-cost-advisor).
- Push remote: SEMPRE chiedere prima.
- Sicurezza: passkey/chiavi/credenziali mai hardcoded; identità dalla sessione/firma, mai dal body.

## Naming
Working name: **Vouchsafe**. Alt: "KYA — Know Your Agent", "Patente Agente", "Agent Mandate".
