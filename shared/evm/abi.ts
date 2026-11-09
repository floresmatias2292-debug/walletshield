/**
 * Decodificador ABI mínimo: solo lo necesario para leer los argumentos de
 * las funciones peligrosas (address, uint, bool, bytes, bytes[]).
 * Cualquier dato malformado lanza AbiError; el analizador lo trata como
 * "no se pudo decodificar" (riesgo, no silencio).
 */
import { strip0x } from './hex';

export class AbiError extends Error {}

const MAX_CALLDATA_HEX = 2_000_000; // ~1 MB
const MAX_ARRAY = 256;

export class AbiReader {
  constructor(private readonly hex: string) {}

  get words(): number {
    return Math.floor(this.hex.length / 64);
  }

  private wordAt(byteOffset: number): string {
    const start = byteOffset * 2;
    if (byteOffset < 0 || start + 64 > this.hex.length) throw new AbiError('fuera de rango');
    return this.hex.slice(start, start + 64);
  }

  uint(i: number): bigint {
    return BigInt(`0x${this.wordAt(i * 32)}`);
  }

  address(i: number): string {
    const w = this.wordAt(i * 32);
    if (!/^0{24}/.test(w)) throw new AbiError('address con bits altos');
    return `0x${w.slice(24)}`.toLowerCase();
  }

  bool(i: number): boolean {
    const v = this.uint(i);
    if (v > 1n) throw new AbiError('bool inválido');
    return v === 1n;
  }

  private offsetAt(i: number): number {
    const o = this.uint(i);
    if (o > BigInt(this.hex.length / 2)) throw new AbiError('offset inválido');
    return Number(o);
  }

  private bytesAtByte(byteOffset: number): string {
    const len = Number(BigInt(`0x${this.wordAt(byteOffset)}`));
    const start = (byteOffset + 32) * 2;
    if (len < 0 || start + len * 2 > this.hex.length) throw new AbiError('bytes fuera de rango');
    return this.hex.slice(start, start + len * 2);
  }

  /** `bytes` dinámico en la posición i (sin 0x). */
  bytes(i: number): string {
    return this.bytesAtByte(this.offsetAt(i));
  }

  /** `bytes[]` dinámico en la posición i. */
  bytesArray(i: number): string[] {
    const base = this.offsetAt(i);
    const n = Number(BigInt(`0x${this.wordAt(base)}`));
    if (n > MAX_ARRAY) throw new AbiError('arreglo demasiado grande');
    const out: string[] = [];
    const head = base + 32;
    for (let k = 0; k < n; k++) {
      const rel = Number(BigInt(`0x${this.wordAt(head + k * 32)}`));
      out.push(this.bytesAtByte(head + rel));
    }
    return out;
  }

  /** `uint256[]` dinámico en la posición i. */
  uintArray(i: number): bigint[] {
    const base = this.offsetAt(i);
    const n = Number(BigInt(`0x${this.wordAt(base)}`));
    if (n > MAX_ARRAY) throw new AbiError('arreglo demasiado grande');
    return Array.from({ length: n }, (_, k) => BigInt(`0x${this.wordAt(base + 32 + k * 32)}`));
  }
}

export interface Calldata {
  readonly selector: string; // "0x12345678"
  readonly args: AbiReader;
}

export function splitCalldata(data: unknown): Calldata | null {
  if (typeof data !== 'string') return null;
  const h = strip0x(data).toLowerCase();
  if (h.length < 8 || h.length > MAX_CALLDATA_HEX || !/^[0-9a-f]*$/.test(h)) return null;
  return { selector: `0x${h.slice(0, 8)}`, args: new AbiReader(h.slice(8)) };
}
