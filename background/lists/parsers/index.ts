import type { SourceId } from '../sources';

export interface ParsedList {
  readonly block: readonly unknown[];
  /** Entradas "host/ruta" explícitas (además de las que vengan mezcladas en block). */
  readonly blockPaths: readonly unknown[];
  readonly allowExact: readonly string[];
  readonly allowWithSubdomains: readonly string[];
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** MetaMask eth-phishing-detect: { version, tolerance, fuzzylist, whitelist, blacklist } */
export function parseMetaMask(json: unknown): ParsedList {
  if (!isObject(json) || !Array.isArray(json.blacklist)) throw new Error('metamask: formato inesperado');
  return { block: json.blacklist, blockPaths: [], allowExact: [], allowWithSubdomains: strings(json.whitelist) };
}

/** polkadot-js/phishing all.json: { allow, deny, denySub } (denySub son rutas "host/ruta") */
export function parsePolkadot(json: unknown): ParsedList {
  if (!isObject(json) || !Array.isArray(json.deny)) throw new Error('polkadot: formato inesperado');
  return {
    block: json.deny,
    blockPaths: Array.isArray(json.denySub) ? json.denySub : [],
    allowExact: strings(json.allow).map((d) => d.replace(/^\*\./, '')),
    allowWithSubdomains: [],
  };
}

/** ScamSniffer domains.json: string[]; archivos diarios: { domains: string[] } */
export function parseScamSniffer(json: unknown): ParsedList {
  if (Array.isArray(json)) return { block: json, blockPaths: [], allowExact: [], allowWithSubdomains: [] };
  if (isObject(json) && Array.isArray(json.domains)) {
    return { block: json.domains, blockPaths: [], allowExact: [], allowWithSubdomains: [] };
  }
  throw new Error('scamsniffer: formato inesperado');
}

export const PARSERS: Record<SourceId, (json: unknown) => ParsedList> = {
  metamask: parseMetaMask,
  polkadot: parsePolkadot,
  scamsniffer: parseScamSniffer,
};
