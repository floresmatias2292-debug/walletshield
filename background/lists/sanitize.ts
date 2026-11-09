import { HOSTING_SUFFIXES, hostAndParents, isValidHostname, registrableDomain } from '../../shared/domain/normalize';
import { LEGIT_DOMAINS, NEVER_BLOCK_EXACT } from '../../shared/domain/legit-domains';

const LEGIT_REGISTRABLES = new Set(LEGIT_DOMAINS.map((l) => registrableDomain(l.domain)));
/** Padres con punto de los dominios legítimos (p. ej. "com.ar" para "x.com.ar"). */
const LEGIT_PARENTS = new Set<string>();
for (const l of LEGIT_REGISTRABLES) for (const p of hostAndParents(l)) if (p !== l) LEGIT_PARENTS.add(p);

export interface AllowLists {
  /** Nunca se bloquea esta entrada exacta. */
  readonly exact: ReadonlySet<string>;
  /** Nunca se bloquea esta entrada ni sus subdominios (whitelist de MetaMask). */
  readonly withSubdomains: ReadonlySet<string>;
}

export const EMPTY_ALLOW: AllowLists = { exact: new Set(), withSubdomains: new Set() };

function isUnderAny(host: string, set: ReadonlySet<string>): boolean {
  if (set.size === 0) return false;
  for (const p of hostAndParents(host)) if (set.has(p)) return true;
  return false;
}

/**
 * Normaliza una entrada de lista pública y descarta las peligrosas:
 *  - inválidas, sin punto, con ruta o puerto;
 *  - plataformas compartidas (bloquearlas rompería miles de sitios);
 *  - dominios legítimos conocidos o sus padres (falso positivo de la lista);
 *  - permitidos por la propia fuente.
 */
export function sanitizeListDomain(raw: unknown, allow: AllowLists = EMPTY_ALLOW): string | null {
  if (typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase();
  if (d.startsWith('*.')) d = d.slice(2);
  if (d.endsWith('.')) d = d.slice(0, -1);
  if (!d.includes('.') || /[/:?#@\s]/.test(d)) return null;
  if (/[^\x00-\x7f]/.test(d)) {
    try {
      d = new URL(`http://${d}`).hostname;
    } catch {
      return null;
    }
  }
  if (!isValidHostname(d)) return null;
  if (NEVER_BLOCK_EXACT.has(d) || HOSTING_SUFFIXES.has(d)) return null;
  if (allow.exact.has(d) || isUnderAny(d, allow.withSubdomains)) return null;
  const reg = registrableDomain(d);
  if (LEGIT_REGISTRABLES.has(reg)) return null; // el dominio o un subdominio de un sitio legítimo
  if (LEGIT_PARENTS.has(d)) return null; // padre de un dominio legítimo
  return d;
}

export function sanitizeAll(list: readonly unknown[], allow: AllowLists = EMPTY_ALLOW): string[] {
  const out = new Set<string>();
  for (const raw of list) {
    const d = sanitizeListDomain(raw, allow);
    if (d) out.add(d);
  }
  return [...out];
}

/** Dominios que la regla "allow" global debe cubrir (con subdominios). */
export function upstreamAllowDomains(withSubdomains: Iterable<string>): string[] {
  const out = new Set<string>(LEGIT_REGISTRABLES);
  for (const d of withSubdomains) if (isValidHostname(d)) out.add(d);
  return [...out].sort();
}

/**
 * Entradas con ruta ("sites.google.com/view/metamask-login"): se bloquean
 * solo esa página, nunca el dominio completo. Devuelve "host/ruta" o null.
 */
export function sanitizeListPath(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().replace(/^https?:\/\//i, '');
  const slash = s.indexOf('/');
  if (slash <= 0) return null;
  const host = s.slice(0, slash).toLowerCase();
  let path = s.slice(slash + 1).split(/[?#]/)[0] ?? '';
  path = path.replace(/\/+$/, '');
  if (!isValidHostname(host) || path.length < 2 || path.length > 300) return null;
  // Solo caracteres seguros: nada de comodines de urlFilter (*, ^, |).
  if (!/^[A-Za-z0-9._~%\-/@]+$/.test(path)) return null;
  if (LEGIT_REGISTRABLES.has(registrableDomain(host))) return null;
  return `${host}/${path}`;
}

export function sanitizePaths(list: readonly unknown[]): string[] {
  const out = new Set<string>();
  for (const raw of list) {
    if (typeof raw !== 'string' || !raw.includes('/')) continue;
    const p = sanitizeListPath(raw);
    if (p) out.add(p);
  }
  return [...out].sort();
}
