# Bozza post LinkedIn — Agent Passport

> Onestà: pubblicalo come "problema che sto esplorando / prototipo che sto costruendo", NON come
> "ho risolto il futuro". Credibilità > hype (protegge la tua reputazione). Idealmente allega lo
> screenshot/video della demo quando c'è (la demo È il post). Sotto, 3 hook + il corpo.
>
> **Media pronti** (in `docs/media/`):
> - `demo.gif` — flusso completo ~16s: mandato valido ✓ → azione fuori-scope rifiutata → **revoca → rifiuto all'istante**. È il media principale del post.
> - `01-valid.png` / `02-scope-denied.png` / `03-revoked.png` — i 3 frame chiave, se preferisci il carosello alla GIF.
> Caption suggerita: *"Stesso agente, stesso token. Prima della revoca: ✓. Dopo: ✗ in tempo reale. Nessun login, solo un mandato umano verificabile."*
>
> **Pilastro 2 (post di follow-up)** — `demo-receipt.gif`: la "ricevuta del contenuto". Stesso
> contenuto + ricevuta → revochi il mandato → la ricevuta passa da VALIDA a REVOCATA all'istante.
> Hook: *"E se ogni output di un agente AI portasse uno scontrino firmato — che puoi spegnere?"*

## Hook (scegline uno)
1. *Continuiamo a chiedere agli agenti AI "sei umano?". È la domanda sbagliata.*
2. *Più del 50% del traffico di internet ora è bot. Il problema non è bloccarli — è sapere chi li ha autorizzati.*
3. *L'economia degli agenti ha un collo di bottiglia, e non è l'intelligenza. È l'identità.*

## Corpo

Più del **50% del traffico di internet è ormai fatto da bot**, e il traffico degli agenti AI è
cresciuto del **450% in un anno**. La nostra unica difesa? Il CAPTCHA — "sei umano?". Una corsa
che stiamo perdendo: l'AI li risolve meglio di noi.

Credo che stiamo facendo la domanda sbagliata.

Davanti a un agente AI che agisce — compra, posta, parla con altri agenti — la domanda utile non
è *"sei umano?"*, è: **"hai il mandato di una persona reale per fare questo, e quel permesso è
ancora valido?"**

Sto esplorando un'idea che chiamo **Agent Passport**: una specie di **patente verificabile e
revocabile per gli agenti AI**. Una persona reale firma un mandato — *cosa* può fare l'agente,
*per quanto*, e con un pulsante per **revocarlo in qualsiasi momento**. Chiunque può verificarlo,
senza dover sapere chi sei. Non reinventa l'identità: si appoggia a quella che hai già (passkey,
ecc.). Aggiunge la parte che oggi manca: **responsabilità + revoca**.

Non è ancora un prodotto, e sono onesto su una cosa: **non ho inventato un nuovo standard.** Google
(AP2, ora donato alla **FIDO Alliance**), il protocollo AIP (IETF draft) e UCAN stanno già
standardizzando il "mandato agentico come credenziale verificabile" — root umana, scope, revoca
sono già lì. Quello che ho costruito è una cosa più modesta e, credo, utile: una **reference
implementation neutrale, eseguibile in 3 comandi**, che mette insieme in *un solo flusso provabile*
ciò che oggi è sparso tra spec e partner — umano firma → l'agente produce → chiunque verifica →
revoca live — più uno **scontrino firmato del contenuto** legato a quel mandato. Complementare a
quegli standard, non in concorrenza.

Ci sto lavorando, open source (Apache-2.0), e nel repo dichiaro anche i **limiti** (la passkey
firma un hash opaco; la non-trasferibilità del root resta aperta). Curioso di sapere cosa ne pensate. 👇

#AI #AIagents #Identity #Crypto #FutureOfWork
