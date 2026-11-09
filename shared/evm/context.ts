/**
 * Contexto del análisis. El analizador es puro y síncrono: cuando necesita
 * un dato on-chain que no tiene, devuelve null y registra la consulta.
 * El orquestador corre el análisis dos veces: la primera solo para recoger
 * las consultas, y la segunda con las respuestas.
 */
import type { RiskLevel } from '../risk';
import { knownContract, TOKEN_DECIMALS } from './known';
import { lookupKey, type Lookup, type TokenInfo } from './types';

export interface AnalysisInput {
  chainId: number | null;
  account: string | null;
  pageHost: string;
  siteRisk: RiskLevel;
  /** Comportamientos sospechosos observados en la página (fase 4). */
  pageThreats?: readonly { readonly risk: RiskLevel; readonly text: string }[];
  now: number;
  badAddresses: ReadonlySet<string>;
  /** Respuestas a consultas, por lookupKey. */
  answers: ReadonlyMap<string, unknown>;
}

export class AnalysisContext {
  readonly pending = new Map<string, Lookup>();
  constructor(readonly input: AnalysisInput) {}

  get chainId(): number | null {
    return this.input.chainId;
  }
  get account(): string | null {
    return this.input.account;
  }
  get now(): number {
    return this.input.now;
  }

  private ask<T>(l: Lookup): T | null {
    const k = lookupKey(l);
    if (this.input.answers.has(k)) return (this.input.answers.get(k) as T | null) ?? null;
    this.pending.set(k, l);
    return null;
  }

  isBad(address: string): boolean {
    return this.input.badAddresses.has(address.toLowerCase());
  }

  /** true contrato, false cuenta personal (EOA), null desconocido. */
  isContract(address: string): boolean | null {
    if (knownContract(address, this.chainId)) return true;
    return this.ask<boolean>({ kind: 'code', address: address.toLowerCase() });
  }

  nativeBalance(address: string): bigint | null {
    return this.ask<bigint>({ kind: 'balance', address: address.toLowerCase() });
  }

  token(address: string): TokenInfo {
    const k = knownContract(address, this.chainId);
    if (k?.kind === 'token') return { symbol: k.label, decimals: TOKEN_DECIMALS[k.label] ?? null };
    return this.ask<TokenInfo>({ kind: 'token', address: address.toLowerCase() }) ?? { symbol: null, decimals: null };
  }

  tokenBalance(token: string, owner: string): bigint | null {
    return this.ask<bigint>({ kind: 'tokenBalance', address: token.toLowerCase(), owner: owner.toLowerCase() });
  }
}
