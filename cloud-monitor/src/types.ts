/** Tipos mínimos del runtime de Workers (sin depender de @cloudflare/workers-types). */
export interface KV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

export interface Env {
  readonly STATE: KV;
  readonly EVM_ADDRESSES?: string;
  readonly SOLANA_ADDRESSES?: string;
  readonly EVM_CHAINS?: string;
  readonly ETH_RPC_URL?: string;
  readonly ARB_RPC_URL?: string;
  readonly SOL_RPC_URL?: string;
  /** Secret: token del bot (wrangler secret put). */
  readonly TELEGRAM_BOT_TOKEN?: string;
  /** Secret: chat id al que se envían las alertas. */
  readonly TELEGRAM_CHAT_ID?: string;
  /** Nivel mínimo a notificar: "info" (todo, por defecto), "media" o "alta". */
  readonly NOTIFY_LEVEL?: string;
  /** Solo para pruebas locales: base de la API de Telegram. */
  readonly TELEGRAM_API_BASE?: string;
}

export type Severity = 'alta' | 'media' | 'info';

export interface Alert {
  readonly severity: Severity;
  readonly chain: string; // "Ethereum", "Arbitrum", "Solana"
  readonly address: string;
  readonly text: string;
  readonly link?: string; // explorador
  readonly revoke?: string; // revoke.cash o equivalente
}
