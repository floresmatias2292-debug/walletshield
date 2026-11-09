import type { Strictness } from './risk';
import { normalizeHost } from './domain/normalize';

export type SourceToggle = { metamask: boolean; polkadot: boolean; scamsniffer: boolean };

export interface Settings {
  readonly version: 1;
  readonly strictness: Strictness;
  readonly sources: SourceToggle;
  /** Sitios de confianza del usuario (hostnames). */
  readonly allowlist: readonly string[];
  /** Consulta RDAP de fecha de registro (envía el dominio a rdap.org). Off por defecto. */
  readonly rdapLookup: boolean;
  /** Firewall de wallets (análisis de firmas y transacciones). */
  readonly firewall: boolean;
  /** Protección del portapapeles (direcciones reemplazadas al copiar/pegar). */
  readonly clipboardGuard: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  version: 1,
  strictness: 'normal',
  sources: { metamask: true, polkadot: true, scamsniffer: true },
  allowlist: [],
  rdapLookup: false,
  firewall: true,
  clipboardGuard: true,
};

const STRICTNESS: readonly Strictness[] = ['relaxed', 'normal', 'strict'];
export const MAX_ALLOWLIST = 2000;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Valida (y normaliza) ajustes que vienen de storage o de un archivo
 * importado por el usuario. Nunca confía en la forma del objeto: lo que no
 * valida se reemplaza por el valor por defecto.
 */
export function parseSettings(input: unknown): Settings {
  if (!isObj(input)) return DEFAULT_SETTINGS;
  const strictness = STRICTNESS.includes(input.strictness as Strictness)
    ? (input.strictness as Strictness)
    : DEFAULT_SETTINGS.strictness;
  const src = isObj(input.sources) ? input.sources : {};
  const sources: SourceToggle = {
    metamask: typeof src.metamask === 'boolean' ? src.metamask : true,
    polkadot: typeof src.polkadot === 'boolean' ? src.polkadot : true,
    scamsniffer: typeof src.scamsniffer === 'boolean' ? src.scamsniffer : true,
  };
  const allowlist: string[] = [];
  if (Array.isArray(input.allowlist)) {
    for (const h of input.allowlist) {
      if (typeof h !== 'string') continue;
      const n = normalizeHost(h);
      if (n && !allowlist.includes(n)) allowlist.push(n);
      if (allowlist.length >= MAX_ALLOWLIST) break;
    }
  }
  return {
    version: 1,
    strictness,
    sources,
    allowlist,
    rdapLookup: input.rdapLookup === true,
    firewall: input.firewall !== false,
    clipboardGuard: input.clipboardGuard !== false,
  };
}
