# WalletShield

Extensión de Chrome (Manifest V3) que protege contra phishing y drainers dirigidos a wallets cripto (MetaMask, Rabby y, opcionalmente, Phantom). Todo el análisis es local: **cero telemetría**. Lo único que sale del navegador es la descarga de las listas públicas de phishing.

> **Estado: fase 2 de 8.** Ya funcionan el bloqueo de phishing por dominio y la detección de imitaciones. El firewall de wallets, la detección de scripts maliciosos, Solana, el popup y opciones, y el monitor en la nube llegan en las próximas fases.

| Fase | Contenido | Estado |
|---|---|---|
| 1 | Arquitectura y plan | ✅ |
| 2 | Bloqueo por dominio (declarativeNetRequest) + heurísticas | ✅ |
| 3 | Firewall de wallets EVM (proxy del provider, decodificador, modal) | ⏳ |
| 4 | Scripts maliciosos y clipboard hijacking | ⏳ |
| 5 | Solana (opcional) | ⏳ |
| 6 | Popup y página de opciones | ⏳ |
| 7 | Monitor en la nube (Ethereum + Arbitrum) con alertas de Telegram | ⏳ |
| 8 | Medición de rendimiento y auditoría de seguridad | ⏳ |

## Instalación en modo desarrollador

Requisitos: Node 20 o superior y Chrome 121 o superior.

```bash
npm ci
```

```bash
npm run build
```

1. Abre `chrome://extensions`.
2. Activa **Modo de desarrollador** (arriba a la derecha).
3. Haz clic en **Cargar descomprimida** y elige la carpeta `dist/`.

Al instalarse, la extensión ya protege con el snapshot de listas empaquetado. En segundo plano descarga las listas actualizadas (unos 14 MB la primera vez, una sola vez).

## Cómo funciona (fase 2)

```
Navegación ──► Motor DNR de Chrome (nativo, sin JS)
                 ├─ dominio en lista ──► redirige a blocked.html
                 ├─ script/iframe/xhr desde dominio en lista ──► bloqueado
                 └─ página en Google Sites listada ──► blocked.html (regla por ruta)
          └──► webNavigation.onBeforeNavigate (service worker)
                 └─ heurísticas: homoglifos, punycode, typosquatting,
                    "marca + claim/airdrop", marca en subdominio ajeno
                    └─ riesgo alto ──► blocked.html?src=h
                       riesgo medio ──► insignia "!" en el ícono
```

### Listas en reglas nativas (declarativeNetRequest)

- El filtrado lo hace el motor de Chrome, no JavaScript. Los ~500.000 dominios **no viven en la memoria de la extensión**. Por eso no hace falta un Bloom filter: la búsqueda O(1) la resuelve Chrome con sus índices.
- Cada fuente reparte sus dominios en *buckets* por hash (FNV‑1a). Cada bucket genera dos reglas: `redirect` para la navegación y `block` para scripts, iframes, XHR y websockets.
- **Snapshot estático:** MetaMask y polkadot vienen empaquetados (`rules/static/`). No hay costo al arrancar.
- **Actualización (alarma cada 6 h):**
  - descarga condicional con `ETag` / `If-Modified-Since`: si no hubo cambios, responde 304 y no se baja nada;
  - si cambió, se calcula el diff por bucket y solo se reescriben los buckets afectados;
  - si un dominio salió de la lista, se deshabilita la regla estática de su bucket (`updateStaticRules`) y una regla dinámica la reemplaza sin ese dominio.
- **ScamSniffer (incremental real):** se leen los archivos diarios `archive/AAAA-MM-DD.json`, que solo traen las altas. La lista completa se descarga una vez por semana para captar las bajas.
- **Protección contra listas rotas:** si una descarga trae menos de la mitad de los dominios que había, se ignora.

### Heurísticas (`shared/domain/`)

| Señal | Ejemplo | Riesgo |
|---|---|---|
| Homoglifos (mismo "esqueleto" visual) | `uniswаp.org` (a cirílica), `0pensea.io`, `metarnask.io` | alto |
| Mezcla de alfabetos en una etiqueta | latín + cirílico | alto |
| Typosquatting (Damerau‑Levenshtein acotado) | `uinswap.org`, `openseoa.app` | alto (marcas ≥7 letras) / medio |
| Marca + palabra gancho | `uniswap-claim.com`, `raydium-airdrop.xyz` | alto |
| Dominio legítimo dentro del subdominio | `app.uniswap.org.secure-login.xyz` | alto |
| Misma marca, otra extensión | `opensea.support`, `uniswap.app` | medio |
| Dominio recién registrado (RDAP, **opcional**) | menos de 30 días | sube de medio a alto |

**Falsos positivos medidos:** sobre el top‑10.000 de dominios más visitados hubo **0 de riesgo alto** y 2 de riesgo medio (`zapier.com` y `rabb.it`, que solo muestran la insignia). El análisis tarda unos 40 µs por dominio. Para repetir la medición:

```bash
npm run eval:heuristics -- top-10000-domains.txt config.json
```

Nivel de estricteza: **relajado** y **normal** muestran la página de bloqueo solo con riesgo alto; **estricto** también con riesgo medio.

## Permisos

| Permiso | Para qué |
|---|---|
| `declarativeNetRequest` | Bloquear dominios de phishing con reglas nativas de Chrome. |
| `webNavigation` | Analizar cada navegación con las heurísticas. |
| `storage` | Ajustes, estado de las listas, contador de bloqueos y registro de eventos. |
| `alarms` | Actualizar las listas cada 6 h sin mantener el worker despierto. |
| `host_permissions: http://*/*, https://*/*` | Necesario para que DNR redirija a la página de bloqueo, y en la fase 3 para inyectar el firewall en cualquier sitio donde haya una wallet. |

No se usa `tabs`, `declarativeNetRequestFeedback`, `scripting` ni `<all_urls>`.

## Seguridad de la propia extensión

- **CSP de páginas propias:** `script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; connect-src 'self' https:`. No hay `eval`, código remoto ni HTML dinámico (solo `textContent`).
- **Mensajes validados:** los mensajes privilegiados (como "continuar al sitio bloqueado") solo se aceptan de páginas de la propia extensión, nunca de content scripts ni de otras extensiones. Además, el dominio a permitir tiene que ser exactamente el que se bloqueó en esa pestaña.
- **"Continuar de todos modos":** exige marcar una casilla y un clic real (`isTrusted`). Solo dura hasta cerrar el navegador (reglas de sesión).
- **La página de bloqueo no funciona dentro de un iframe** (anti-clickjacking, verificado en el test e2e).
- **Listas:** solo se descargan por HTTPS, con límite de tamaño, y se parsean con `JSON.parse`.

## Limitaciones (fase 2)

- **Las heurísticas actúan al empezar la navegación:** el servidor sospechoso puede llegar a recibir la petición antes de la redirección. No se ejecuta nada en la página, pero la visita queda registrada en ese servidor. El bloqueo por lista (DNR) no tiene este problema.
- **Detección de la extensión:** `blocked.html` tiene que ser *web accessible* para que DNR pueda redirigir a ella. Un sitio podría detectar así que tienes WalletShield instalado. Chrome no permite la variante `use_dynamic_url` con redirecciones DNR; lo verificamos.
- **Sufijos públicos:** no se incluye la Public Suffix List completa, solo un subconjunto (sufijos multinivel comunes y plataformas de hosting gratuito).
- **RDAP desactivado por defecto:** si lo activas, el nombre del dominio sospechoso se envía a rdap.org y al registro correspondiente.
- **Demora de ScamSniffer:** su repo público se publica con 7 días de demora.

## Tests

```bash
npm test
```

```bash
npm run typecheck
```

El test end-to-end carga `dist/` en Chromium con Playwright. Usa servidores locales que imitan GitHub, con listas modificadas a propósito (un dominio quitado, otros agregados), y verifica el diff, el bloqueo, las heurísticas, los falsos positivos y el flujo "continuar". Necesita las listas reales en una carpeta:

```bash
mkdir -p /tmp/ws-lists && curl -sS -o /tmp/ws-lists/mm.json https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json && curl -sS -o /tmp/ws-lists/pd.json https://raw.githubusercontent.com/polkadot-js/phishing/master/all.json
```

```bash
WS_LISTS_DIR=/tmp/ws-lists npm run e2e
```

Con `WS_SS_REAL=1` y `ss_domains.json` en la misma carpeta, el test usa la lista real completa de ScamSniffer (365.000 dominios, prueba de escala).

## Actualizar el snapshot empaquetado

```bash
npm run build:rules
```

Regenera `rules/static/*.json` y `rules/static/meta.json` (cantidades, sha256 y descartes) a partir de las listas actuales. Las listas se actualizan solas en ejecución, así que esto solo hace falta antes de publicar una versión.

## Licencia

Código: MIT (`LICENSE`). Las listas empaquetadas tienen sus propias licencias: ver `SOURCES.md` y `LICENSES/`.
