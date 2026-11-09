/** Estado persistido en Workers KV (una sola clave: 1 escritura por ejecución). */
import type { Alert, KV } from './types';

export interface ChainState {
  block: number; // último bloque revisado
  nonces: Record<string, number>;
  failures: number;
}

export interface State {
  evm: Record<string, ChainState>;
  sol: Record<string, { lastSig: string | null; failures: number }>;
  lastRun: number;
  /** Alertas que no se pudieron enviar (se reintentan en la próxima ejecución). */
  pending: Alert[];
}

const KEY = 'state:v1';

export async function loadState(kv: KV): Promise<State> {
  const raw = await kv.get(KEY);
  if (!raw) return { evm: {}, sol: {}, lastRun: 0, pending: [] };
  try {
    const s = JSON.parse(raw) as State;
    return { evm: s.evm ?? {}, sol: s.sol ?? {}, lastRun: s.lastRun ?? 0, pending: Array.isArray(s.pending) ? s.pending : [] };
  } catch {
    return { evm: {}, sol: {}, lastRun: 0, pending: [] };
  }
}

export async function saveState(kv: KV, s: State): Promise<void> {
  await kv.put(KEY, JSON.stringify(s));
}
