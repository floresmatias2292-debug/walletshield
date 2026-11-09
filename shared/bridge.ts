/**
 * Protocolo entre el script MAIN (contexto de la página) y el script
 * ISOLATED (contexto aislado de la extensión). Viaja por un MessagePort
 * privado que la página no puede ver. Igual se valida todo mensaje.
 */
export const HANDSHAKE_KEY = '__walletshield_port_v1__';

/** Métodos que se analizan antes de llegar a la wallet. El resto pasa directo. */
export const SENSITIVE_METHODS: ReadonlySet<string> = new Set([
  'eth_sendTransaction',
  'eth_signTransaction',
  'eth_sign',
  'personal_sign',
  'eth_signTypedData',
  'eth_signTypedData_v1',
  'eth_signTypedData_v3',
  'eth_signTypedData_v4',
  'wallet_sendCalls',
  'wallet_grantPermissions',
  'wallet_addEthereumChain',
]);

/** Lecturas que ISOLATED puede pedir a la wallet a través de MAIN (sin popups, sin firmas). */
export const READONLY_RPC: ReadonlySet<string> = new Set(['eth_chainId', 'eth_accounts', 'eth_getCode', 'eth_getBalance', 'eth_call']);

export interface FrameInfo {
  readonly top: boolean;
  readonly w: number;
  readonly h: number;
}

export type MainToIso =
  | { t: 'req'; id: number; method: string; params: unknown[]; frame: FrameInfo; ns: 'evm' | 'solana' }
  | { t: 'rpc-res'; id: number; ok: boolean; result: unknown };

export type IsoToMain =
  | { t: 'ack'; id: number }
  | { t: 'decision'; id: number; allow: boolean }
  | { t: 'rpc'; id: number; reqId: number; method: string; params: unknown[] };

const MAX_METHOD = 64;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
const isId = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;

export function parseMainToIso(v: unknown): MainToIso | null {
  if (!isObj(v)) return null;
  if (v.t === 'req') {
    if (!isId(v.id) || typeof v.method !== 'string' || v.method.length > MAX_METHOD || !Array.isArray(v.params)) return null;
    const f = v.frame;
    if (!isObj(f) || typeof f.top !== 'boolean' || typeof f.w !== 'number' || typeof f.h !== 'number') return null;
    if (v.ns !== 'evm' && v.ns !== 'solana') return null;
    return { t: 'req', id: v.id, method: v.method, params: v.params, frame: { top: f.top, w: f.w, h: f.h }, ns: v.ns };
  }
  if (v.t === 'rpc-res' && isId(v.id) && typeof v.ok === 'boolean') return { t: 'rpc-res', id: v.id, ok: v.ok, result: v.result };
  return null;
}

export function parseIsoToMain(v: unknown): IsoToMain | null {
  if (!isObj(v)) return null;
  if (v.t === 'ack' && isId(v.id)) return { t: 'ack', id: v.id };
  if (v.t === 'decision' && isId(v.id) && typeof v.allow === 'boolean') return { t: 'decision', id: v.id, allow: v.allow };
  if (v.t === 'rpc' && isId(v.id) && isId(v.reqId) && typeof v.method === 'string' && READONLY_RPC.has(v.method) && Array.isArray(v.params)) {
    return { t: 'rpc', id: v.id, reqId: v.reqId, method: v.method, params: v.params };
  }
  return null;
}

/** Copia segura (JSON) de parámetros arbitrarios de la página; null si no se puede. */
export function safeClone(v: unknown, maxLen = 2_000_000): unknown[] | null {
  try {
    const s = JSON.stringify(v, (_k, x: unknown) => (typeof x === 'bigint' ? `0x${x.toString(16)}` : x));
    if (s === undefined || s.length > maxLen) return null;
    const out: unknown = JSON.parse(s);
    return Array.isArray(out) ? out : out === null || out === undefined ? [] : [out];
  } catch {
    return null;
  }
}
