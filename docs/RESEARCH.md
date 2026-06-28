# Research — fonti & findings (deep-dive 28 giu 2026)

Sintesi delle 4 ricerche profonde che hanno portato qui. Conclusione: "provare un umano" = muro
o già preso; la crepa vera e attaccabile da un team piccolo = **mandato umano revocabile per
agenti (Know-Your-Agent)**, un layer sopra root-of-trust esistenti.

## Findings chiave
- **Non-trasferibilità / collusion-resistance è irrisolvibile dalla crittografia** (Ohlhaver,
  "Compressed to 0"): filtrare "umani che agiscono come bot" ≡ collusion-resistance. È economia,
  non codice. Idena collassò in puppeteering (23 entità ~40% account).
- **Trilemma personhood** (unico + privato + decentralizzato) = congettura NON dimostrata
  impossibile (Laskus, Douceur 2002 è teorema *condizionale*). Crepa teorica esiste ma stretta.
- **Biometria**: entropia iride sufficiente (Daugman), ma soglia×scala + spoofing = limite
  ingegneristico; World ha già vinto la scala (18M).
- **Primitivi maturi post-2022** che cambiano l'equazione: zkPassport (ICAO in ZK on-device),
  RLN/Semaphore (1 azione per identità), MPC dedup biometrico, BBS+ selective disclosure, zkTLS
  (Reclaim/zkPass), WebAuthn attestation.
- **L'AI rompe** CAPTCHA (~99.8%), Idena flip (~60%), video-selfie/liveness (deepfake injection,
  detection umana 24.5%). La difesa NON è rilevare l'AI (corsa persa) ma certificare il mandato.
- **Convergenza di tutte e 4 le ricerche**: l'unica fessura per un team piccolo = **KYA /
  delegated-authority**, layer sopra root esistente, prototipo in settimane.

## Fonti primarie
- Personhood Credentials — Adler et al., arXiv:2408.07892 — https://arxiv.org/abs/2408.07892
- Buterin, biometric proof of personhood — https://vitalik.eth.limo/general/2023/07/24/biometric.html
- Ohlhaver, "Compressed to 0" (Harvard Ash) — https://ash.harvard.edu/wp-content/uploads/2024/06/proof-of-personhood_ohlhaver.pdf
- Douceur, The Sybil Attack (2002) — https://link.springer.com/chapter/10.1007/3-540-45748-8_24
- Who Watches the Watchmen (survey) — https://arxiv.org/pdf/2008.05300
- MPC iris uniqueness — https://arxiv.org/html/2405.04463
- ZKPassport — https://github.com/zkpassport/circuits
- RLN / Semaphore — https://rate-limiting-nullifier.github.io/rln-docs/what_is_rln.html
- W3C BBS Cryptosuites — https://www.w3.org/TR/vc-di-bbs/
- zkTLS (Reclaim) — https://blog.reclaimprotocol.org/posts/zktls-canon
- A Cryptographic Framework for PoP — IACR ePrint 2026/333 — https://eprint.iacr.org/2026/333
- a16z crypto, AI needs crypto / identity bottleneck — https://a16zcrypto.com/posts/article/ai-needs-crypto-now/
- Bot >50% traffic — https://www.nbcnews.com/tech/tech-news/bot-web-traffic-overtaken-human-web-traffic-data-shows-rcna348522
- World ID 18M + partnership — https://www.axios.com/2026/04/17/worldcoin-zoom-shopify-retail-partnership
