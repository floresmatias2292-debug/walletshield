/**
 * Escaneo diferido de los scripts de la página contra las firmas de kits de
 * drainers. Solo corre si la página usa un provider de wallet, en un momento
 * ocioso, y una sola vez: en el resto de las páginas el costo es cero.
 */
import { matchRules, type ScriptHit } from '../../shared/scripts/signatures';

const MAX_TOTAL = 3 * 1024 * 1024;
const MAX_SCRIPTS = 40;
const FETCH_TIMEOUT = 1500;

async function sha256(text: string): Promise<string | null> {
  try {
    if (!crypto.subtle) return null; // solo en contextos seguros (https)
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

async function fetchSameOrigin(src: string): Promise<string | null> {
  try {
    const u = new URL(src, location.href);
    if (u.origin !== location.origin) return null; // los de otros orígenes ya pasan por las listas DNR
    const res = await fetch(u.href, { cache: 'force-cache', credentials: 'same-origin', signal: AbortSignal.timeout(FETCH_TIMEOUT) });
    if (!res.ok) return null;
    const t = await res.text();
    return t.length > MAX_TOTAL ? t.slice(0, MAX_TOTAL) : t;
  } catch {
    return null;
  }
}

let running: Promise<ScriptHit[]> | null = null;

export function scanScripts(): Promise<ScriptHit[]> {
  running ??= (async () => {
    const hits = new Map<string, ScriptHit>();
    let total = 0;
    const scripts = [...document.scripts].slice(0, MAX_SCRIPTS);
    for (const s of scripts) {
      if (total > MAX_TOTAL) break;
      const code = s.src ? await fetchSameOrigin(s.src) : s.textContent;
      if (!code) continue;
      total += code.length;
      for (const h of matchRules(code, await sha256(code))) hits.set(h.id, h);
    }
    return [...hits.values()];
  })();
  return running;
}

/** Programa el escaneo cuando el navegador esté ocioso. */
export function scheduleScan(onHits: (hits: ScriptHit[]) => void): void {
  const run = () => void scanScripts().then((h) => h.length && onHits(h));
  if ('requestIdleCallback' in window) requestIdleCallback(run, { timeout: 3000 });
  else setTimeout(run, 500);
}
