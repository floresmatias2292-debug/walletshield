/**
 * Fuentes de listas de phishing. Ver SOURCES.md para licencias.
 *
 * - metamask y polkadot se empaquetan además como snapshot estático (reglas
 *   DNR nativas, costo cero al arrancar) y en ejecución solo se aplica el diff.
 * - scamsniffer (GPL-3.0) NUNCA se empaqueta: se descarga en tiempo de
 *   ejecución, así el código de la extensión puede ser MIT.
 */
export type SourceId = 'metamask' | 'polkadot' | 'scamsniffer';

export interface SourceDef {
  readonly id: SourceId;
  readonly name: string;
  readonly url: string;
  readonly license: string;
  /** Cantidad de buckets (grupos) en que se reparten sus dominios. */
  readonly buckets: number;
  /** Primer ID de regla dinámica reservado para esta fuente. */
  readonly dynamicBase: number;
  /** ID del ruleset estático empaquetado, si tiene. */
  readonly staticRuleset?: string;
  /** Archivo diario con solo las altas (descarga incremental real). */
  readonly archiveUrl?: (date: string) => string;
}

export const SOURCES: Record<SourceId, SourceDef> = {
  metamask: {
    id: 'metamask',
    name: 'MetaMask eth-phishing-detect',
    url: 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json',
    license: 'DBAD-1.2',
    buckets: 128,
    dynamicBase: 10_000,
    staticRuleset: 'static_metamask',
  },
  polkadot: {
    id: 'polkadot',
    name: 'polkadot-js/phishing',
    url: 'https://raw.githubusercontent.com/polkadot-js/phishing/master/all.json',
    license: 'Apache-2.0',
    buckets: 64,
    dynamicBase: 20_000,
    staticRuleset: 'static_polkadot',
  },
  scamsniffer: {
    id: 'scamsniffer',
    name: 'ScamSniffer scam-database',
    url: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json',
    license: 'GPL-3.0 (descargada, no empaquetada)',
    buckets: 512,
    dynamicBase: 30_000,
    archiveUrl: (date) =>
      `https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/archive/${date}.json`,
  },
};

export const SOURCE_IDS = Object.keys(SOURCES) as SourceId[];

/** IDs de reglas dinámicas fijas. */
export const RULE_ID_USER_ALLOW = 1;
export const RULE_ID_UPSTREAM_ALLOW = 2;

export const PRIORITY_BLOCK = 1;
export const PRIORITY_UPSTREAM_ALLOW = 50;
export const PRIORITY_USER_ALLOW = 100;

/** Ruta de la página de bloqueo dentro de la extensión. */
export const BLOCKED_PAGE_PATH = '/blocked/blocked.html';
