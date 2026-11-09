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
  /**
   * Simulación de transacciones con Tenderly (opcional, off por defecto).
   * La API key NO vive aquí: se guarda aparte ("secret:tenderlyKey") y nunca
   * se exporta ni llega a los content scripts.
   */
  readonly simulation: { readonly enabled: boolean; readonly account: string; readonly project: string };
}

export const DEFAULT_SETTINGS: Settings = {
  version: 1,
  strictness: 'normal',
  sources: { metamask: true, polkadot: true, scamsniffer: true },
  allowlist: [],
  rdapLookup: false,
  firewall: true,
  clipboardGuard: true,
  simulation: { enabled: false, account: '', project: '' },
};

const SLUG_RE = /^[A-Za-z0-9_.-]{1,64}$/;

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
    simulation: parseSimulation(input.simulation),
  };
}

function parseSimulation(v: unknown): Settings['simulation'] {
  if (!isObj(v)) return DEFAULT_SETTINGS.simulation;
  const account = typeof v.account === 'string' && SLUG_RE.test(v.account) ? v.account : '';
  const project = typeof v.project === 'string' && SLUG_RE.test(v.project) ? v.project : '';
  return { enabled: v.enabled === true && account !== '' && project !== '', account, project };
}

/** Subconjunto que necesitan los content scripts (sin listas ni secretos). */
export interface ContentConfig {
  readonly strictness: Settings['strictness'];
  readonly firewall: boolean;
  readonly clipboardGuard: boolean;
  readonly simulation: boolean;
}

export function contentConfig(s: Settings): ContentConfig {
  return { strictness: s.strictness, firewall: s.firewall, clipboardGuard: s.clipboardGuard, simulation: s.simulation.enabled };
}

/** Archivo de exportación: ajustes validados, sin secretos. */
export function exportSettings(s: Settings): string {
  return JSON.stringify({ app: 'WalletShield', exportedAt: new Date().toISOString(), settings: s }, null, 2);
}

export function importSettings(text: string): Settings {
  if (text.length > 512 * 1024) throw new Error('El archivo es demasiado grande.');
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('El archivo no es JSON válido.');
  }
  if (!isObj(data) || data.app !== 'WalletShield' || !isObj(data.settings)) throw new Error('No es un archivo de configuración de WalletShield.');
  return parseSettings(data.settings);
}
