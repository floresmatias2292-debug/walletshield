/**
 * Simulación opcional de transacciones con Tenderly. Solo corre si el usuario
 * la activó y cargó su API key; envía la transacción a api.tenderly.co.
 * El resultado es INFORMATIVO: se muestra en el modal, no decide por sí solo.
 *
 * Endpoint, cuerpo y respuesta tomados del SDK oficial (github.com/Tenderly/
 * tenderly-sdk, lib/executors/Simulator.ts y Simulator.types.ts, 2026-11-09):
 *   POST https://api.tenderly.co/api/v2/account/{account}/project/{project}/simulations/simulate
 *   cabecera X-Access-Key
 *   cuerpo { network_id, call_args: { from, to, data, value, ... }, block_number_or_hash: { blockNumber } }
 *   respuesta { status, logs: [{ name, inputs: [{ name, value }], raw: { address } }], ... }
 */
import type { SimTx } from '../shared/messages';

export interface SimChange {
  readonly kind: 'out' | 'in' | 'approval';
  readonly token: string;
  readonly amount: string;
  readonly counterparty: string;
}

export interface SimResult {
  readonly ok: boolean;
  readonly reverted?: boolean;
  readonly changes?: readonly SimChange[];
  readonly error?: string;
}

const TIMEOUT_MS = 4000;
export const TENDERLY_API = 'https://api.tenderly.co/api/v2';

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Obj) : null);
const ADDR = /^0x[0-9a-fA-F]{40}$/;

function arg(inputs: unknown, names: readonly string[]): string | null {
  if (!Array.isArray(inputs)) return null;
  for (const i of inputs) {
    const o = obj(i);
    if (o && typeof o.name === 'string' && names.includes(o.name) && (typeof o.value === 'string' || typeof o.value === 'number' || typeof o.value === 'boolean')) {
      return String(o.value);
    }
  }
  return null;
}

/** Deriva movimientos de activos de los logs decodificados (Transfer / Approval). */
export function parseTenderly(json: unknown, from: string): SimResult {
  const root = obj(json);
  if (!root || !('status' in root) || !Array.isArray(root.logs)) return { ok: false, error: 'respuesta inesperada de Tenderly' };
  const me = from.toLowerCase();
  const changes: SimChange[] = [];
  for (const l of root.logs.slice(0, 100)) {
    const log = obj(l);
    const token = typeof obj(log?.raw)?.address === 'string' ? String(obj(log?.raw)?.address).toLowerCase() : '';
    if (!log || !ADDR.test(token)) continue;
    if (log.name === 'Transfer') {
      const f = (arg(log.inputs, ['from', '_from', 'src']) ?? '').toLowerCase();
      const t = (arg(log.inputs, ['to', '_to', 'dst']) ?? '').toLowerCase();
      const amount = (arg(log.inputs, ['value', '_value', 'wad', 'amount', 'tokenId', '_tokenId']) ?? '?').slice(0, 80);
      if (f === me) changes.push({ kind: 'out', token, amount, counterparty: t });
      else if (t === me) changes.push({ kind: 'in', token, amount, counterparty: f });
    } else if (log.name === 'Approval' || log.name === 'ApprovalForAll') {
      const owner = (arg(log.inputs, ['owner', '_owner', 'src']) ?? '').toLowerCase();
      if (owner !== me) continue;
      const spender = (arg(log.inputs, ['spender', '_spender', 'guy', 'operator', '_operator']) ?? '').toLowerCase();
      const amount = (arg(log.inputs, ['value', '_value', 'wad', 'approved', '_approved']) ?? '?').slice(0, 80);
      changes.push({ kind: 'approval', token, amount, counterparty: spender });
    }
  }
  return { ok: true, reverted: root.status === false, changes: changes.slice(0, 30) };
}

export async function simulate(
  cfg: { account: string; project: string; key: string },
  chainId: number,
  blockNumber: number | null,
  tx: SimTx,
  fetchImpl: typeof fetch = fetch,
): Promise<SimResult> {
  try {
    const res = await fetchImpl(`${TENDERLY_API}/account/${encodeURIComponent(cfg.account)}/project/${encodeURIComponent(cfg.project)}/simulations/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Access-Key': cfg.key },
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      body: JSON.stringify({
        network_id: String(chainId),
        call_args: { from: tx.from, to: tx.to, data: tx.data, value: tx.value, gas: 8_000_000, gas_price: '0' },
        ...(blockNumber !== null ? { block_number_or_hash: { blockNumber } } : {}),
      }),
    });
    if (res.status === 401 || res.status === 403) return { ok: false, error: 'API key de Tenderly inválida' };
    if (!res.ok) return { ok: false, error: `Tenderly respondió ${res.status}` };
    return parseTenderly(await res.json(), tx.from);
  } catch (e) {
    return { ok: false, error: e instanceof Error && e.name === 'TimeoutError' ? 'Tenderly no respondió a tiempo' : 'no se pudo contactar a Tenderly' };
  }
}
