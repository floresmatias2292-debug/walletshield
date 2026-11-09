/**
 * Ejecuta las consultas on-chain que pide el analizador, a través de la
 * propia wallet (vía el script MAIN). Solo lecturas: eth_getCode,
 * eth_getBalance y eth_call a decimals/symbol/balanceOf.
 */
import { lookupKey, type Lookup, type TokenInfo } from '../../shared/evm/types';
import { SEL } from '../../shared/evm/selectors';
import { hexToBytes, bytesToText, toBigInt } from '../../shared/evm/hex';

export type Rpc = (method: string, params: unknown[]) => Promise<unknown>;

function decodeString(hex: unknown): string | null {
  if (typeof hex !== 'string' || !hex.startsWith('0x')) return null;
  const h = hex.slice(2);
  try {
    if (h.length >= 128) {
      const len = Number(BigInt(`0x${h.slice(64, 128)}`));
      if (len > 0 && len <= 64) {
        const b = hexToBytes(h.slice(128, 128 + len * 2));
        const s = b ? bytesToText(b) : null;
        if (s) return s.slice(0, 16);
      }
    }
    if (h.length === 64) {
      const b = hexToBytes(h.replace(/(00)+$/, ''));
      const s = b ? bytesToText(b) : null;
      if (s) return s.slice(0, 16); // tokens viejos con bytes32 (MKR, SAI)
    }
  } catch {
    /* inválido */
  }
  return null;
}

async function one(rpc: Rpc, l: Lookup): Promise<unknown> {
  switch (l.kind) {
    case 'code': {
      const code = await rpc('eth_getCode', [l.address, 'latest']);
      return typeof code === 'string' ? code !== '0x' && code !== '0x0' : null;
    }
    case 'balance':
      return toBigInt(await rpc('eth_getBalance', [l.address, 'latest']));
    case 'tokenBalance': {
      const data = SEL.balanceOf + l.owner.slice(2).padStart(64, '0');
      return toBigInt(await rpc('eth_call', [{ to: l.address, data }, 'latest']));
    }
    case 'token': {
      const [sym, dec] = await Promise.allSettled([
        rpc('eth_call', [{ to: l.address, data: SEL.symbol }, 'latest']),
        rpc('eth_call', [{ to: l.address, data: SEL.decimals }, 'latest']),
      ]);
      const symbol = sym.status === 'fulfilled' ? decodeString(sym.value) : null;
      const d = dec.status === 'fulfilled' ? toBigInt(dec.value) : null;
      const info: TokenInfo = { symbol: symbol ? symbol.replace(/[^\w.$-]/g, '') : null, decimals: d !== null && d <= 36n ? Number(d) : null };
      return info;
    }
  }
}

export async function resolveLookups(rpc: Rpc, lookups: readonly Lookup[]): Promise<Map<string, unknown>> {
  const out = new Map<string, unknown>();
  const results = await Promise.allSettled(lookups.map((l) => one(rpc, l)));
  results.forEach((r, i) => {
    const l = lookups[i]!;
    out.set(lookupKey(l), r.status === 'fulfilled' ? r.value : null);
  });
  return out;
}
