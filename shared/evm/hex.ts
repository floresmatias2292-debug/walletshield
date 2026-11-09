/** Utilidades hex/bigint sin dependencias. */

export const MAX_UINT256 = (1n << 256n) - 1n;
/**
 * A partir de este monto una aprobación se trata como "ilimitada":
 * 2^100 ≈ 1,27e30, o sea más de un billón de tokens con 18 decimales.
 * Cubre 2^256-1, 2^255, 2^160-1 (máximo de Permit2) y otros valores "infinitos".
 */
export const UNLIMITED_THRESHOLD = 1n << 100n;

export function isUnlimited(v: bigint): boolean {
  return v >= UNLIMITED_THRESHOLD;
}

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

export function isAddress(v: unknown): v is string {
  return typeof v === 'string' && ADDR_RE.test(v);
}

/** Dirección en minúsculas, o null si no es válida. */
export function normAddr(v: unknown): string | null {
  return isAddress(v) ? v.toLowerCase() : null;
}

export function isZeroAddress(a: string): boolean {
  return /^0x0{40}$/i.test(a);
}

/** Convierte números en formatos JSON-RPC habituales a bigint. */
export function toBigInt(v: unknown): bigint | null {
  try {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^0x[0-9a-fA-F]{0,64}$/.test(s)) return s === '0x' ? 0n : BigInt(s);
      if (/^\d{1,80}$/.test(s)) return BigInt(s);
    }
  } catch {
    /* formato inválido */
  }
  return null;
}

export function strip0x(h: string): string {
  return h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h;
}

export function isHex(v: unknown): v is string {
  return typeof v === 'string' && /^0x[0-9a-fA-F]*$/.test(v) && v.length % 2 === 0;
}

export function hexToBytes(h: string): Uint8Array | null {
  const s = strip0x(h);
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Decodifica UTF-8 estricto; null si no es texto válido o tiene caracteres de control raros. */
export function bytesToText(b: Uint8Array): string | null {
  try {
    const s = new TextDecoder('utf-8', { fatal: true }).decode(b);
    // eslint-disable-next-line no-control-regex
    return /[\x00-\x08\x0e-\x1f\x7f]/.test(s) ? null : s;
  } catch {
    return null;
  }
}
