/**
 * Escaneo de una cadena EVM: una consulta eth_getLogs (por tramo de bloques)
 * para todas las direcciones + nonces en un solo lote JSON-RPC.
 */
import { knownContract } from '../../shared/evm/known';
import type { ChainCfg } from './config';
import { rpcBatch, type Call } from './rpc';
import type { ChainState } from './state';
import type { Alert, Severity } from './types';

// keccak256 de las firmas de eventos (verificado en tests/evm.test.ts)
export const T = {
  transfer: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef', // Transfer(address,address,uint256)
  approval: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925', // Approval(address,address,uint256)
  approvalForAll: '0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31', // ApprovalForAll(address,address,bool)
  permit2Approval: '0xda9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b', // Approval(address,address,address,uint160,uint48)
  permit2Permit: '0xc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec', // Permit(address,address,address,uint160,uint48,uint48)
} as const;

const UNLIMITED = 1n << 100n;

export interface Log {
  address: string;
  topics: string[];
  data: string;
  transactionHash: string;
  logIndex?: string;
}

const pad = (a: string) => `0x${a.slice(2).toLowerCase().padStart(64, '0')}`;
const topicAddr = (t: string | undefined) => (t && t.length === 66 ? `0x${t.slice(26)}`.toLowerCase() : '');
const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const hexNum = (h: unknown) => (typeof h === 'string' && /^0x[0-9a-fA-F]+$/.test(h) ? Number.parseInt(h, 16) : NaN);
function word(data: string, i: number): bigint {
  const h = data.replace(/^0x/, '').slice(i * 64, i * 64 + 64);
  return h ? BigInt(`0x${h}`) : 0n;
}

function label(addr: string, chainId: number): string {
  const k = knownContract(addr, chainId);
  return k ? `${k.label} (${short(addr)})` : short(addr);
}

function tokenName(addr: string, chainId: number): { name: string; known: boolean; decimals: number | null } {
  const k = knownContract(addr, chainId);
  const DEC: Record<string, number> = { WETH: 18, USDC: 6, USDT: 6, DAI: 18, WBTC: 8, stETH: 18, wstETH: 18, ARB: 18 };
  return k?.kind === 'token' ? { name: k.label, known: true, decimals: DEC[k.label] ?? null } : { name: `token ${short(addr)}`, known: false, decimals: null };
}

function amount(v: bigint, decimals: number | null): string {
  if (v >= UNLIMITED) return 'ILIMITADO';
  if (decimals === null) return `${v} unidades`;
  const base = 10n ** BigInt(decimals);
  const frac = (v % base).toString().padStart(decimals, '0').slice(0, 4).replace(/0+$/, '');
  return `${(v / base).toLocaleString('es-AR')}${frac ? `,${frac}` : ''}`;
}

/** Convierte logs en alertas. `nonceChanged`: la dirección firmó transacciones en este intervalo. */
export function logsToAlerts(cfg: ChainCfg, logs: readonly Log[], watched: ReadonlySet<string>, nonceChanged: ReadonlySet<string>): Alert[] {
  const alerts: Alert[] = [];
  const revoke = (a: string) => `https://revoke.cash/address/${a}?chainId=${cfg.id}`;
  const tx = (h: string) => `${cfg.explorer}/tx/${h}`;
  let poisoningNoted = new Set<string>();
  for (const l of logs) {
    const t0 = l.topics[0]?.toLowerCase();
    const owner = topicAddr(l.topics[1]);
    if (!watched.has(owner)) continue;
    const token = l.address.toLowerCase();
    const base = { chain: cfg.name, address: owner, link: tx(l.transactionHash) };
    if (t0 === T.approval && l.topics.length === 3) {
      const spender = topicAddr(l.topics[2]);
      const v = word(l.data, 0);
      if (v === 0n) continue; // revocación
      const tk = tokenName(token, cfg.id);
      const known = !!knownContract(spender, cfg.id);
      const sev: Severity = v >= UNLIMITED && !known ? 'alta' : known ? 'info' : 'media';
      alerts.push({ ...base, severity: sev, revoke: revoke(owner), text: `Nueva aprobación: ${label(spender, cfg.id)} puede mover ${amount(v, tk.decimals)} de ${tk.name}.` });
    } else if (t0 === T.approval && l.topics.length === 4) {
      const approved = topicAddr(l.topics[2]);
      if (/^0x0{40}$/.test(approved)) continue;
      alerts.push({ ...base, severity: 'media', revoke: revoke(owner), text: `Aprobación de un NFT (#${BigInt(l.topics[3] ?? '0x0')}) de ${label(token, cfg.id)} a ${label(approved, cfg.id)}.` });
    } else if (t0 === T.approvalForAll) {
      const operator = topicAddr(l.topics[2]);
      if (word(l.data, 0) === 0n) continue;
      const known = !!knownContract(operator, cfg.id);
      alerts.push({ ...base, severity: known ? 'media' : 'alta', revoke: revoke(owner), text: `Acceso TOTAL (setApprovalForAll) a tu colección ${label(token, cfg.id)} para ${label(operator, cfg.id)}.` });
    } else if (t0 === T.permit2Approval || t0 === T.permit2Permit) {
      const tk = tokenName(topicAddr(l.topics[2]), cfg.id);
      const spender = topicAddr(l.topics[3]);
      const v = word(l.data, 0);
      if (v === 0n) continue;
      const known = !!knownContract(spender, cfg.id);
      alerts.push({
        ...base,
        severity: known ? 'info' : 'alta',
        revoke: revoke(owner),
        text: `Permiso de Permit2${t0 === T.permit2Permit ? ' (por firma)' : ''}: ${label(spender, cfg.id)} puede mover ${amount(v, tk.decimals)} de ${tk.name}.`,
      });
    } else if (t0 === T.transfer) {
      const to = topicAddr(l.topics[2]);
      const nft = l.topics.length === 4;
      const v = nft ? 1n : word(l.data, 0);
      const tk = tokenName(token, cfg.id);
      if (!nft && v === 0n) {
        if (!poisoningNoted.has(owner)) {
          alerts.push({ ...base, severity: 'info', text: `Transferencia de 0 ${tk.name} "desde" tu dirección: es spam de address poisoning. No copies direcciones de tu historial.` });
          poisoningNoted = new Set([...poisoningNoted, owner]);
        }
        continue;
      }
      const what = nft ? `el NFT #${BigInt(l.topics[3] ?? '0x0')} de ${label(token, cfg.id)}` : `${amount(v, tk.decimals)} ${tk.name}`;
      if (!nonceChanged.has(owner)) {
        // Salieron activos sin que tu cuenta firmara nada: los movió alguien con un permiso tuyo.
        alerts.push({
          ...base,
          severity: tk.known || nft ? 'alta' : 'media',
          revoke: revoke(owner),
          text: `Salieron ${what} hacia ${short(to)} SIN una transacción tuya: alguien con un permiso tuyo los movió.${tk.known || nft ? '' : ' (Si no conoces este token, puede ser spam.)'}`,
        });
      } else {
        alerts.push({ ...base, severity: 'media', revoke: revoke(owner), text: `Enviaste ${what} a ${short(to)}.` });
      }
    }
  }
  return alerts;
}

export interface ChainResult {
  readonly alerts: Alert[];
  readonly state: ChainState;
  readonly baseline: boolean;
}

export async function scanChain(cfg: ChainCfg, addresses: readonly string[], prev: ChainState | undefined, fetchImpl: typeof fetch = fetch): Promise<ChainResult> {
  const head = await rpcBatch(cfg.rpc, [{ method: 'eth_blockNumber', params: [] }, ...addresses.map((a) => ({ method: 'eth_getTransactionCount', params: [a, 'latest'] }))], fetchImpl);
  const latest = hexNum(head[0]);
  if (!Number.isFinite(latest)) throw new Error('eth_blockNumber inválido');
  const nonces: Record<string, number> = {};
  addresses.forEach((a, i) => {
    const n = hexNum(head[i + 1]);
    if (Number.isFinite(n)) nonces[a] = n;
  });
  const safeHead = latest - cfg.confirmations;

  if (!prev) return { alerts: [], state: { block: safeHead, nonces, failures: 0 }, baseline: true };

  const alerts: Alert[] = [];
  const changed = new Set<string>();
  for (const a of addresses) {
    const before = prev.nonces[a];
    const now = nonces[a];
    if (before === undefined || now === undefined) continue;
    if (now > before) {
      changed.add(a);
      alerts.push({
        severity: 'media',
        chain: cfg.name,
        address: a,
        link: `${cfg.explorer}/address/${a}`,
        text: `Se firmaron ${now - before} transacción(es) con tu cuenta. Si NO fuiste tú, tu clave está comprometida: mueve lo que quede a una wallet nueva.`,
      });
    }
  }

  const from = prev.block + 1;
  const to = Math.min(safeHead, from + cfg.maxRange - 1);
  let block = prev.block;
  if (from <= to && addresses.length) {
    const topics = [[T.transfer, T.approval, T.approvalForAll, T.permit2Approval, T.permit2Permit], addresses.map(pad)];
    const calls: Call[] = [];
    for (let s = from; s <= to; s += cfg.chunk) {
      const e = Math.min(to, s + cfg.chunk - 1);
      calls.push({ method: 'eth_getLogs', params: [{ fromBlock: `0x${s.toString(16)}`, toBlock: `0x${e.toString(16)}`, topics }] });
    }
    const results = await rpcBatch(cfg.rpc, calls, fetchImpl);
    const logs = results.flatMap((r) => (Array.isArray(r) ? (r as Log[]) : []));
    alerts.push(...logsToAlerts(cfg, logs, new Set(addresses), changed));
    block = to;
  } else if (from > to) {
    block = prev.block;
  }
  return { alerts, state: { block, nonces: { ...prev.nonces, ...nonces }, failures: 0 }, baseline: false };
}
