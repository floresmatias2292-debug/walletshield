# WalletShield: monitor en la nube

Vigila tus direcciones **públicas** de Ethereum, Arbitrum y Solana cada 10 minutos, aunque tu computadora esté apagada, y te avisa por **Telegram**.

Corre en **Cloudflare Workers** (plan gratuito) con un Cron Trigger. No necesitas servidor propio.

> **Nunca** pongas aquí una clave privada ni una frase semilla. El monitor solo necesita direcciones públicas, y si detecta algo con forma de clave privada o frase semilla, se niega a arrancar.

## Qué detecta

| Cadena | Evento | Alerta |
|---|---|---|
| Ethereum / Arbitrum | Aprobación nueva de un token (ilimitada o a un contrato desconocido) | 🚨 alta |
| | `setApprovalForAll` (acceso a toda una colección de NFTs) | 🚨 alta (marketplace conocido: ⚠️) |
| | Permiso de Permit2 (`Approval` o `Permit` por firma) a un desconocido | 🚨 alta |
| | **Salen tokens o NFTs sin que tu cuenta haya firmado nada**: alguien los movió con un permiso tuyo (drainer) | 🚨 alta |
| | Se firmaron transacciones con tu cuenta (cambió el nonce; incluye envíos de ETH) | ⚠️ media |
| | Envíos de tokens hechos por ti | ⚠️ media |
| | Transferencia de 0 "desde" tu dirección (address poisoning) | ℹ️ info |
| Solana | Cambio de dueño de una cuenta de tokens (`SetAuthority`), `Assign` de tu wallet | 🚨 alta |
| | Delegación ilimitada (`Approve`) | 🚨 alta |
| | Cambio de autoridad de staking o de durable nonce | 🚨 alta |
| | Salidas de SOL o tokens | ⚠️ media |

Cada alerta trae el enlace a la transacción en el explorador y, en EVM, a **revoke.cash** con la cadena ya elegida.

## Instalación (unos 15 minutos)

Necesitas Node 20 o superior y una cuenta gratuita de Cloudflare.

### 1. Crea tu bot de Telegram

1. En Telegram, habla con **@BotFather** y envía `/newbot`. Te da un **token** con este formato: `123456789:AA…`. No lo compartas.
2. Escríbele cualquier mensaje a tu bot nuevo; si no lo haces, el bot no puede escribirte.
3. Abre en el navegador la dirección de abajo, reemplazando `TU_TOKEN`. Busca `"chat":{"id": …}`: ese número es tu **chat id**.

```text
https://api.telegram.org/botTU_TOKEN/getUpdates
```

### 2. Prepara el proyecto

```bash
cd cloud-monitor
```

```bash
npm ci
```

Opcional: desactiva la telemetría de la herramienta `wrangler` de Cloudflare. No es del monitor, pero envía estadísticas de uso de la CLI.

```bash
npx wrangler telemetry disable
```

```bash
npx wrangler login
```

### 3. Crea el almacenamiento del estado (KV)

```bash
npx wrangler kv namespace create STATE
```

Copia el `id` que te devuelve y pégalo en `wrangler.toml`, en lugar de `REEMPLAZAR_CON_TU_KV_ID`.

### 4. Pon tus direcciones públicas en `wrangler.toml`

```toml
EVM_ADDRESSES = "0xTuDireccion1,0xTuDireccion2"
SOLANA_ADDRESSES = "TuDireccionDeSolana"
```

Opcional:
- `NOTIFY_LEVEL = "media"` o `"alta"` reduce los avisos. Con `"info"`, el valor por defecto, también te avisa de cada transacción que firmes.
- Puedes cambiar los RPC por los tuyos; ver "Limitaciones".

### 5. Guarda los secretos (no van en ningún archivo)

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
```

```bash
npx wrangler secret put TELEGRAM_CHAT_ID
```

### 6. Despliega

```bash
npx wrangler deploy
```

En 10 minutos como máximo recibirás en Telegram: **"Monitor activo: vigilando N dirección(es)…"**. Para ver los logs en vivo:

```bash
npx wrangler tail
```

## Costos (plan gratuito de Cloudflare)

- **144 ejecuciones por día**, una cada 10 minutos.
- **1 escritura de KV por ejecución:** 144 al día, del límite gratuito de 1.000.
- **Pocas llamadas a otros servicios por ejecución:**
  - 2 a 3 lotes JSON-RPC por cadena EVM (todas tus direcciones van en una misma consulta);
  - hasta 2 por cada dirección de Solana;
  - 1 por mensaje de Telegram.

## Seguridad y privacidad

- **Solo direcciones públicas:** el monitor se niega a correr si ve una clave privada o una frase semilla.
- **Token de Telegram como secret de Cloudflare:** nunca aparece en el código, en los logs ni en los mensajes de error.
- **Solo HTTPS:** los RPC y la API de Telegram deben usar HTTPS. HTTP se acepta únicamente hacia `localhost`, para pruebas.
- **URL pública mínima:** solo responde "WalletShield monitor activo.", sin direcciones ni estado.
- **Qué ven terceros:**
  - Cloudflare ve tus direcciones (están en la configuración del Worker);
  - el proveedor de RPC ve qué direcciones consultas;
  - Telegram ve el contenido de las alertas.
- **Si Telegram falla:** las alertas quedan guardadas y se reenvían en la siguiente ejecución.

## Limitaciones

- **Solo avisa, no frena:** el monitor no puede detener un drenaje. Su valor es que te enteres en minutos y no días después, para revocar permisos y mover lo que quede.
- **Demora:** hasta 10 minutos, más las confirmaciones (3 bloques en Ethereum, 20 en Arbitrum).
- **Firmas que todavía no se usaron:** un Permit firmado se ve recién cuando el atacante lo ejecuta en la cadena (aparece como `Approval`/`Permit` o como salida de tokens). Hasta entonces es invisible para cualquier monitor on-chain.
- **RPC públicos:** tienen límites de uso y a veces fallan. Si una cadena falla 3 veces seguidas, recibes un aviso y el monitor retoma desde el último bloque revisado, sin perder eventos. Para más confiabilidad, usa un RPC propio gratuito (Alchemy, Infura o QuickNode para EVM; Helius para Solana).
- **Solana:**
  - se analizan como máximo 10 transacciones nuevas por dirección y por ejecución; si hay más, te avisa;
  - no hay un equivalente verificado de revoke.cash para Solana, así que se enlaza a Solscan y se recomienda revocar delegaciones desde tu wallet.
- **Tokens de spam:** los tokens desconocidos se marcan con menor severidad, porque muchos son spam de address poisoning.

## ¿Por qué Cloudflare Workers y no GitHub Actions?

- **Demoras:** los workflows programados de GitHub Actions suelen ejecutarse con minutos u horas de retraso en momentos de carga.
- **Desactivación:** GitHub desactiva los workflows programados de repos públicos sin actividad durante 60 días.
- **Cuotas:** consumen minutos de Actions.

Los Cron Triggers de Cloudflare corren puntuales y gratis.

## Pruebas

Los tests unitarios (desde la raíz del repo) cubren:
- configuración;
- detección EVM y Solana;
- recorrido de bloques en tramos;
- fallas del RPC;
- reenvío de alertas pendientes;
- formato de los mensajes de Telegram.

```bash
npx vitest run cloud-monitor
```

Prueba en el runtime real de Cloudflare (`workerd`, con `wrangler dev`). Usa RPC y Telegram simulados localmente y no despliega nada:

```bash
cd cloud-monitor && node tests/e2e-local.mjs
```
