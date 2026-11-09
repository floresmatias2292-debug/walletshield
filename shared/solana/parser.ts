/**
 * Parser de transacciones de Solana (formato "wire" con firmas, o solo el
 * mensaje), legacy y v0. No necesita RPC. Las cuentas que vienen de Address
 * Lookup Tables (v0) no se pueden resolver localmente: se representan como
 * "tabla#índice".
 */
import { encodeBase58 } from './base58';

export class SolParseError extends Error {}

export interface SolInstruction {
  readonly programId: string;
  readonly accounts: readonly string[];
  readonly data: Uint8Array;
}

export interface SolMessage {
  readonly version: 'legacy' | 0;
  readonly signers: readonly string[];
  readonly feePayer: string;
  readonly staticKeys: readonly string[];
  readonly instructions: readonly SolInstruction[];
  readonly lookupTables: number;
}

const MAX_KEYS = 256;
const MAX_IX = 128;

class Reader {
  pos = 0;
  constructor(readonly b: Uint8Array) {}
  u8(): number {
    if (this.pos >= this.b.length) throw new SolParseError('fin inesperado');
    return this.b[this.pos++]!;
  }
  bytes(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.b.length) throw new SolParseError('fin inesperado');
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  /** compact-u16 ("shortvec"). */
  shortvec(): number {
    let len = 0;
    for (let i = 0; i < 3; i++) {
      const v = this.u8();
      len |= (v & 0x7f) << (7 * i);
      if ((v & 0x80) === 0) return len;
    }
    throw new SolParseError('shortvec inválido');
  }
}

export function parseMessage(bytes: Uint8Array): SolMessage {
  const r = new Reader(bytes);
  let version: 'legacy' | 0 = 'legacy';
  const first = r.b[0];
  if (first !== undefined && first & 0x80) {
    const v = r.u8() & 0x7f;
    if (v !== 0) throw new SolParseError(`versión ${v} no soportada`);
    version = 0;
  }
  const numSigners = r.u8();
  r.u8(); // readonly firmados
  r.u8(); // readonly no firmados
  const nKeys = r.shortvec();
  if (nKeys > MAX_KEYS || nKeys < numSigners) throw new SolParseError('cuentas inválidas');
  const staticKeys: string[] = [];
  for (let i = 0; i < nKeys; i++) staticKeys.push(encodeBase58(r.bytes(32)));
  r.bytes(32); // blockhash reciente
  const nIx = r.shortvec();
  if (nIx > MAX_IX) throw new SolParseError('demasiadas instrucciones');
  const raw: Array<{ p: number; a: number[]; d: Uint8Array }> = [];
  for (let i = 0; i < nIx; i++) {
    const p = r.u8();
    const na = r.shortvec();
    const a: number[] = [];
    for (let k = 0; k < na; k++) a.push(r.u8());
    const d = r.bytes(r.shortvec());
    raw.push({ p, a, d });
  }
  const lookupKeys: string[] = [];
  let lookupTables = 0;
  if (version === 0) {
    const nLut = r.shortvec();
    lookupTables = nLut;
    const writable: string[] = [];
    const readonly: string[] = [];
    for (let i = 0; i < nLut; i++) {
      const table = encodeBase58(r.bytes(32));
      const short = `${table.slice(0, 4)}…`;
      const nw = r.shortvec();
      for (let k = 0; k < nw; k++) writable.push(`tabla:${short}#${r.u8()}`);
      const nr = r.shortvec();
      for (let k = 0; k < nr; k++) readonly.push(`tabla:${short}#${r.u8()}`);
    }
    lookupKeys.push(...writable, ...readonly);
  }
  const all = [...staticKeys, ...lookupKeys];
  const key = (i: number): string => {
    const k = all[i];
    if (k === undefined) throw new SolParseError('índice de cuenta inválido');
    return k;
  };
  const instructions = raw.map((x) => ({ programId: key(x.p), accounts: x.a.map(key), data: x.d }));
  return {
    version,
    signers: staticKeys.slice(0, numSigners),
    feePayer: staticKeys[0] ?? '',
    staticKeys,
    instructions,
    lookupTables,
  };
}

/** Transacción completa: shortvec de firmas (64 bytes c/u) + mensaje. */
export function parseWireTransaction(bytes: Uint8Array): SolMessage {
  const r = new Reader(bytes);
  const nSig = r.shortvec();
  if (nSig > 64) throw new SolParseError('demasiadas firmas');
  r.bytes(nSig * 64);
  return parseMessage(bytes.subarray(r.pos));
}

/** Intenta como transacción completa y, si no, como mensaje. */
export function parseAny(bytes: Uint8Array, wire: boolean): SolMessage {
  if (wire) return parseWireTransaction(bytes);
  return parseMessage(bytes);
}

export function u64le(d: Uint8Array, off: number): bigint {
  if (off + 8 > d.length) throw new SolParseError('u64 fuera de rango');
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(d[off + i]!);
  return v;
}

export function u32le(d: Uint8Array, off: number): number {
  if (off + 4 > d.length) throw new SolParseError('u32 fuera de rango');
  return (d[off]! | (d[off + 1]! << 8) | (d[off + 2]! << 16) | (d[off + 3]! << 24)) >>> 0;
}
