# Fuentes de listas de phishing

Licencias verificadas el 2026-11-09 leyendo el archivo `LICENSE` de cada repositorio.

| Fuente | Licencia | Cómo se usa | Tamaño (nov 2026) |
|---|---|---|---|
| [MetaMask/eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) `src/config.json` | DBAD Public License 1.2 (`LICENSES/eth-phishing-detect-DBAD.md`) | Snapshot estático empaquetado + diff en ejecución. Su `whitelist` se respeta siempre. | 118.448 dominios |
| [polkadot-js/phishing](https://github.com/polkadot-js/phishing) `all.json` | Apache-2.0 (`LICENSES/polkadot-js-phishing-Apache-2.0.txt`) | Snapshot estático empaquetado + diff en ejecución. Sus `allow` se respetan; `denySub` se bloquea por ruta. | 54.863 dominios |
| [scamsniffer/scam-database](https://github.com/scamsniffer/scam-database) `blacklist/domains.json` + `blacklist/archive/AAAA-MM-DD.json` | **GPL-3.0** | **No se empaqueta.** Se descarga en tiempo de ejecución y se carga como reglas dinámicas. Así el código de WalletShield puede ser MIT. | 360.360 dominios |

## Notas

- **ScamSniffer publica su repo público con 7 días de demora** (lo dice su README). Lo más nuevo solo está en su API de pago, que no se usa.
- `address.json` de ScamSniffer **no se actualiza desde febrero de 2024**: no se usa como fuente principal de direcciones de drainers.
- MetaMask tiene una API con diffs reales (`phishing-detection.api.cx.metamask.io`). No se usa porque sus términos para terceros no están claros; se usa el repo de GitHub con ETag.

## Entradas descartadas a propósito

Las listas reales contienen entradas que bloquearían miles de sitios legítimos, por ejemplo `sites.google.com`, `storage.googleapis.com`, `r2.dev` y `cloudflare-ipfs.com` (ScamSniffer, nov 2026). `background/lists/sanitize.ts` las descarta:

- plataformas compartidas (`NEVER_BLOCK_EXACT` en `shared/domain/legit-domains.ts`): se bloquean sus subdominios, nunca la plataforma entera;
- dominios legítimos conocidos (Uniswap, OpenSea, Jupiter…) o sus dominios padre;
- entradas inválidas (`text`, `chromewebdata`, `ad`, con puerto, etc.).

Las entradas con ruta (`sites.google.com/view/metamask-login/...`, 1.564 en MetaMask) se bloquean **solo en esa página** con una regla `urlFilter`.
