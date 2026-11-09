import { isUnlimited } from './hex';
import { knownContract } from './known';
import type { AnalysisContext } from './context';

export function shortAddr(a: string): string {
  return `${a.slice(0, 6)}…${a.slice(-4)}`;
}

export function formatUnits(v: bigint, decimals: number | null): string {
  if (decimals === null || decimals < 0 || decimals > 36) return v.toString();
  const base = 10n ** BigInt(decimals);
  const whole = v / base;
  const frac = v % base;
  if (frac === 0n) return whole.toLocaleString('es-AR');
  const fracStr = frac.toString().padStart(decimals, '0').slice(0, 6).replace(/0+$/, '');
  return `${whole.toLocaleString('es-AR')}${fracStr ? `,${fracStr}` : ''}`;
}

/** "1.000 USDC", "ILIMITADO de USDC", "123 (token 0xabcd…1234)". */
export function formatAmount(ctx: AnalysisContext, token: string, amount: bigint): string {
  const t = ctx.token(token);
  const name = t.symbol ?? `token ${shortAddr(token)}`;
  if (isUnlimited(amount)) return `ILIMITADO de ${name}`;
  return `${formatUnits(amount, t.decimals)} ${name}`;
}

export function formatEth(wei: bigint, chainId: number | null): string {
  return `${formatUnits(wei, 18)} ${chainId === 42161 ? 'ETH (Arbitrum)' : 'ETH'}`;
}

/** Nombre legible de una dirección: etiqueta conocida o abreviatura. */
export function describeAddress(ctx: AnalysisContext, a: string): string {
  const k = knownContract(a, ctx.chainId);
  if (k) return `${k.label} (${shortAddr(a)})`;
  return shortAddr(a);
}

/** Vencimiento en segundos UNIX → frase completa ("vence en 30 días", "no vence nunca"). */
export function formatExpiry(ctx: AnalysisContext, ts: bigint): string {
  const nowS = BigInt(Math.floor(ctx.now / 1000));
  if (ts === 0n || ts > nowS + 100n * 365n * 86400n) return 'no vence nunca';
  if (ts <= nowS) return 'ya venció';
  const days = Number((ts - nowS) / 86400n);
  if (days < 1) return 'vence en menos de un día';
  if (days < 60) return `vence en ${days} días`;
  if (days < 730) return `vence en ${Math.round(days / 30)} meses`;
  return `vence en ${Math.round(days / 365)} años`;
}

export function expiryDays(ctx: AnalysisContext, ts: bigint): number {
  const nowS = BigInt(Math.floor(ctx.now / 1000));
  if (ts === 0n) return Infinity; // EIP-2612 DAI: expiry 0 = sin vencimiento
  if (ts <= nowS) return 0;
  const d = (ts - nowS) / 86400n;
  return d > 100_000n ? Infinity : Number(d);
}
