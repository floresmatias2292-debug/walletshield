/**
 * Detección de direcciones cripto en texto y comparación para detectar
 * reemplazos en el portapapeles (clipboard hijacking) y "address poisoning"
 * (direcciones falsas que se parecen al principio y al final).
 */
const EVM_RE = /0x[a-fA-F0-9]{40}/g;
const BTC_RE = /\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const SOL_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;

export type AddressKind = 'evm' | 'btc' | 'solana';

export interface FoundAddress {
  readonly kind: AddressKind;
  readonly value: string;
}

const MAX_TEXT = 10_000;

export function findAddresses(text: string): FoundAddress[] {
  if (!text) return [];
  const t = text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text;
  const out: FoundAddress[] = [];
  const seen = new Set<string>();
  const push = (kind: AddressKind, value: string) => {
    const key = kind === 'evm' ? value.toLowerCase() : value;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, value });
  };
  for (const m of t.matchAll(EVM_RE)) push('evm', m[0]);
  const noEvm = t.replace(EVM_RE, ' ');
  for (const m of noEvm.matchAll(BTC_RE)) push('btc', m[0]);
  for (const m of noEvm.matchAll(SOL_RE)) {
    // base58 de 32-44 caracteres con mayúsculas, minúsculas y dígitos (evita palabras largas)
    if (/[A-Z]/.test(m[0]) && /[a-z]/.test(m[0]) && /\d/.test(m[0]) && !seen.has(m[0])) push('solana', m[0]);
  }
  return out;
}

export function sameAddress(a: FoundAddress | string, b: FoundAddress | string): boolean {
  const x = typeof a === 'string' ? a : a.value;
  const y = typeof b === 'string' ? b : b.value;
  return /^0x/i.test(x) && /^0x/i.test(y) ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/** Caracteres iguales al principio y al final (sin el prefijo 0x). */
function edgeMatch(a: string, b: string): { head: number; tail: number } {
  const x = a.replace(/^0x/i, '').toLowerCase();
  const y = b.replace(/^0x/i, '').toLowerCase();
  let head = 0;
  while (head < x.length && head < y.length && x[head] === y[head]) head++;
  let tail = 0;
  while (tail < x.length - head && tail < y.length - head && x[x.length - 1 - tail] === y[y.length - 1 - tail]) tail++;
  return { head, tail };
}

/**
 * Dos direcciones distintas que comparten ≥3 caracteres al inicio y ≥3 al
 * final: el patrón de las direcciones "vanity" que generan los atacantes
 * para que la víctima no note el cambio.
 */
export function isLookalike(a: string, b: string): boolean {
  if (sameAddress(a, b)) return false;
  const { head, tail } = edgeMatch(a, b);
  return head >= 3 && tail >= 3;
}

export function shortAddress(a: string): string {
  return a.length > 14 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a;
}
