/**
 * Escaneo de una dirección de Solana: firmas nuevas desde la última revisada
 * y análisis de las instrucciones "parsed" del RPC.
 */
import { rpcBatch } from './rpc';
import type { Alert } from './types';

const MAX_TX = 10;
const U64_HALF = (1n << 63n);
const short = (a: string) => `${a.slice(0, 4)}…${a.slice(-4)}`;

interface ParsedIx {
  program?: string;
  parsed?: { type?: string; info?: Record<string, unknown> };
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function lamports(v: unknown): string {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? `${(n / 1e9).toLocaleString('es-AR', { maximumFractionDigits: 6 })} SOL` : '? SOL';
}

/** Instrucciones (externas e internas) de una transacción jsonParsed. */
export function instructionsOf(tx: unknown): ParsedIx[] {
  const t = tx as { transaction?: { message?: { instructions?: unknown[] } }; meta?: { innerInstructions?: Array<{ instructions?: unknown[] }> } } | null;
  const outer = t?.transaction?.message?.instructions ?? [];
  const inner = (t?.meta?.innerInstructions ?? []).flatMap((x) => x.instructions ?? []);
  return [...outer, ...inner] as ParsedIx[];
}

export function solTxToAlerts(owner: string, sig: string, tx: unknown): Alert[] {
  const alerts: Alert[] = [];
  const base = { chain: 'Solana', address: owner, link: `https://solscan.io/tx/${sig}` };
  for (const ix of instructionsOf(tx)) {
    const type = ix.parsed?.type;
    const info = ix.parsed?.info ?? {};
    if (!type) continue;
    if (ix.program === 'spl-token') {
      const authority = str(info.authority) || str(info.multisigAuthority) || str(info.owner);
      if (type === 'setAuthority' && authority === owner) {
        const kind = str(info.authorityType);
        alerts.push({
          ...base,
          severity: kind === 'accountOwner' || kind === 'closeAccount' ? 'alta' : 'media',
          text: `Cambió la autoridad "${kind}" de tu cuenta de tokens ${short(str(info.account))} a ${short(str(info.newAuthority) || '?')}. Si no fuiste tú, ya no controlas esos tokens.`,
        });
      } else if ((type === 'approve' || type === 'approveChecked') && authority === owner) {
        const raw = str((info.tokenAmount as { amount?: unknown } | undefined)?.amount) || str(info.amount);
        let unlimited = false;
        try {
          unlimited = raw !== '' && BigInt(raw) >= U64_HALF;
        } catch {
          /* monto ilegible */
        }
        alerts.push({ ...base, severity: unlimited ? 'alta' : 'media', text: `Delegaste ${unlimited ? 'TODO el saldo (ilimitado)' : `${raw || '?'} unidades`} de una cuenta de tokens a ${short(str(info.delegate))}.` });
      } else if ((type === 'transfer' || type === 'transferChecked') && authority === owner) {
        const amt = str((info.tokenAmount as { uiAmountString?: unknown } | undefined)?.uiAmountString) || str(info.amount);
        alerts.push({ ...base, severity: 'media', text: `Salieron ${amt || '?'} tokens${info.mint ? ` (${short(str(info.mint))})` : ''} hacia ${short(str(info.destination))}.` });
      }
    } else if (ix.program === 'system') {
      if ((type === 'assign' || type === 'assignWithSeed') && str(info.account) === owner) {
        alerts.push({ ...base, severity: 'alta', text: `Tu cuenta fue asignada al programa ${short(str(info.owner))} ("owner change"). Puede que hayas perdido el control de la wallet.` });
      } else if ((type === 'transfer' || type === 'transferWithSeed') && str(info.source) === owner) {
        alerts.push({ ...base, severity: 'media', text: `Salieron ${lamports(info.lamports)} hacia ${short(str(info.destination))}.` });
      } else if (type === 'authorizeNonce' && str(info.nonceAuthority) === owner) {
        alerts.push({ ...base, severity: 'alta', text: `Cambió la autoridad de una cuenta "durable nonce" a ${short(str(info.newAuthorized))}.` });
      }
    } else if (ix.program === 'stake' && (type === 'authorize' || type === 'authorizeChecked' || type === 'authorizeWithSeed') && str(info.authority) === owner) {
      alerts.push({ ...base, severity: 'alta', text: `Cambió la autoridad de tu cuenta de staking ${short(str(info.stakeAccount))} a ${short(str(info.newAuthority))}.` });
    }
  }
  return alerts;
}

export interface SolResult {
  readonly alerts: Alert[];
  readonly lastSig: string | null;
  readonly baseline: boolean;
}

export async function scanSolana(rpcUrl: string, owner: string, lastSig: string | null | undefined, fetchImpl: typeof fetch = fetch): Promise<SolResult> {
  const opts: Record<string, unknown> = { limit: 25, commitment: 'confirmed' };
  if (lastSig) opts.until = lastSig;
  const [sigsRaw] = await rpcBatch(rpcUrl, [{ method: 'getSignaturesForAddress', params: [owner, opts] }], fetchImpl);
  const sigs = (Array.isArray(sigsRaw) ? sigsRaw : []) as Array<{ signature?: string }>;
  const newest = sigs[0]?.signature ?? lastSig ?? null;
  if (lastSig === undefined) return { alerts: [], lastSig: newest, baseline: true };
  const fresh = sigs.map((s) => s.signature).filter((s): s is string => typeof s === 'string').slice(0, MAX_TX);
  if (!fresh.length) return { alerts: [], lastSig: newest, baseline: false };
  const txs = await rpcBatch(
    rpcUrl,
    fresh.map((s) => ({ method: 'getTransaction', params: [s, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }] })),
    fetchImpl,
  );
  const alerts = txs.flatMap((t, i) => solTxToAlerts(owner, fresh[i]!, t));
  if (sigs.length > MAX_TX) {
    alerts.push({ severity: 'info', chain: 'Solana', address: owner, link: `https://solscan.io/account/${owner}`, text: `Hubo ${sigs.length}+ transacciones nuevas; se analizaron las ${MAX_TX} más recientes.` });
  }
  return { alerts, lastSig: newest, baseline: false };
}
