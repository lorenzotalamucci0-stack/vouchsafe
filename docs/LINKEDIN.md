# Bozza post LinkedIn — Vouchsafe

> Onestà: pubblicalo come "problema che sto esplorando / prototipo", NON come "ho risolto il futuro".
> Credibilità > hype. Il media principale è la demo della **ricevuta che muore alla revoca**.
>
> **Media pronti** (in `docs/media/`):
> - `demo-receipt.gif` — il cuore: contenuto + ricevuta VALIDA → revochi → **REVOCATA all'istante**. Media principale.
> - `demo.gif` — il mandato: azione valida → revoca → rifiuto live. Secondario / carosello.
> Caption: *"Stesso contenuto, stessa ricevuta. Prima della revoca: ✓. Dopo: ✗ in tempo reale."*

## Hook (scegline uno)
1. *Un agente AI ha scritto questo. Chi l'ha autorizzato — ed è ancora valido?*
2. *Marcare un contenuto come "fatto da AI" è facile. Provare CHI l'ha autorizzato, e poterlo spegnere, no.*
3. *E se ogni output di un agente AI portasse uno scontrino firmato che puoi revocare?*

## Corpo

Gli agenti AI scrivono, postano, agiscono al posto nostro. La domanda di oggi — *"questo è
generato da AI?"* — è quella che già risolvono il watermarking e C2PA. Ma ne manca una più utile:

**"chi ha autorizzato questo output, per fare cosa, ed è ancora valido adesso?"**

Sto costruendo **Vouchsafe**: una persona autorizza un agente firmando con la sua **passkey**; ogni
output dell'agente porta una **ricevuta firmata** legata a quell'autorizzazione; e se la persona
**revoca**, la ricevuta **smette di valere all'istante**.

Il pezzo che non ho trovato in nessun altro: la **revoca che uccide lo scontrino, in tempo reale,
sui contenuti**. I sistemi di provenienza (C2PA) sono *foto immutabili del passato*; gli audit-log
firmati per agenti (Signet) restano *validi per sempre*; il mandato-con-passkey di Google AP2 vive
*nei pagamenti*. Vouchsafe mette le tre cose insieme — consenso umano + scontrino sul contenuto +
revoca viva — ed è eseguibile in locale in pochi comandi.

Sono onesto su due cose. **Non è un nuovo standard**: mandato, delega e revoca esistono già
(AP2/FIDO, AIP, UCAN). E **non ti rende "conforme all'EU AI Act Art. 50" da solo** — Art.50 chiede
il *marking*; Vouchsafe aggiunge il layer di **accountability** che gli sta accanto: chi ha
autorizzato, con che scope, ancora valido. Utile proprio dal 2 agosto 2026.

Open source (Apache-2.0). Nel repo dichiaro anche i limiti (la passkey firma un hash opaco; la
non-trasferibilità del root resta aperta). Curioso di sapere cosa ne pensate. 👇

#AI #AIagents #AIGovernance #EUAIAct #ContentAuthenticity
