/**
 * Lógica pura (sin APIs de Chrome) para convertir listas de dominios en
 * reglas declarativeNetRequest y calcular el mínimo de cambios necesario.
 *
 * Cada fuente reparte sus dominios en N buckets por hash. Cada bucket se
 * traduce en dos reglas:
 *   - "redirect" (main_frame) → página de bloqueo propia,
 *   - "block" (sub_frame, script, xhr, websocket) → corta drainers cargados
 *     desde dominios de phishing por sitios comprometidos.
 * Un cambio en la lista solo toca los buckets afectados.
 */
import { BLOCKED_PAGE_PATH, PRIORITY_BLOCK } from './sources';

type Rule = chrome.declarativeNetRequest.Rule;

/** FNV-1a de 32 bits: estable entre build y runtime. */
export function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export function bucketOf(domain: string, buckets: number): number {
  return fnv1a(domain) % buckets;
}

export function bucketize(domains: Iterable<string>, buckets: number): string[][] {
  const out: string[][] = Array.from({ length: buckets }, () => []);
  for (const d of domains) out[bucketOf(d, buckets)]!.push(d);
  for (const b of out) b.sort();
  return out;
}

export const SUBRESOURCE_TYPES: chrome.declarativeNetRequest.ResourceType[] = [
  'sub_frame' as chrome.declarativeNetRequest.ResourceType,
  'script' as chrome.declarativeNetRequest.ResourceType,
  'xmlhttprequest' as chrome.declarativeNetRequest.ResourceType,
  'websocket' as chrome.declarativeNetRequest.ResourceType,
];

/** IDs de las dos reglas de un bucket dado un ID base. */
export function bucketRuleIds(base: number, bucket: number): [redirect: number, block: number] {
  return [base + bucket * 2, base + bucket * 2 + 1];
}

export function rulesForBucket(base: number, bucket: number, domains: readonly string[]): Rule[] {
  if (domains.length === 0) return [];
  const [redirectId, blockId] = bucketRuleIds(base, bucket);
  return [
    {
      id: redirectId,
      priority: PRIORITY_BLOCK,
      action: {
        type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
        redirect: { extensionPath: BLOCKED_PAGE_PATH },
      },
      condition: {
        requestDomains: [...domains],
        resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
      },
    },
    {
      id: blockId,
      priority: PRIORITY_BLOCK,
      action: { type: 'block' as chrome.declarativeNetRequest.RuleActionType },
      condition: { requestDomains: [...domains], resourceTypes: SUBRESOURCE_TYPES },
    },
  ];
}

export interface StaticPlan {
  /** Reglas del ruleset estático a deshabilitar (el bucket perdió dominios). */
  readonly disableStaticRuleIds: number[];
  /** Contenido deseado de cada bucket dinámico (solo buckets no vacíos). */
  readonly dynamicBuckets: Map<number, string[]>;
}

/**
 * Para una fuente con snapshot estático, decide por bucket:
 *  - igual al snapshot → nada dinámico;
 *  - solo altas → regla dinámica con las altas;
 *  - hubo bajas → se deshabilita la regla estática y la dinámica lleva el bucket completo.
 * Sin fuente estática (snapshot vacío) todo es dinámico.
 */
export function planSource(snapshot: readonly string[][] | null, current: readonly string[][]): StaticPlan {
  const disableStaticRuleIds: number[] = [];
  const dynamicBuckets = new Map<number, string[]>();
  current.forEach((bucket, i) => {
    const snap = snapshot?.[i] ?? [];
    if (snap.length === 0) {
      if (bucket.length) dynamicBuckets.set(i, bucket);
      return;
    }
    const cur = new Set(bucket);
    const removed = snap.some((d) => !cur.has(d));
    if (removed) {
      disableStaticRuleIds.push(...bucketRuleIds(1, i));
      if (bucket.length) dynamicBuckets.set(i, bucket);
    } else {
      const snapSet = new Set(snap);
      const added = bucket.filter((d) => !snapSet.has(d));
      if (added.length) dynamicBuckets.set(i, added);
    }
  });
  return { disableStaticRuleIds, dynamicBuckets };
}

export interface DynamicDiff {
  readonly removeRuleIds: number[];
  readonly addRules: Rule[];
}

function sameDomains(a: readonly string[] | undefined, b: readonly string[]): boolean {
  if (!a || a.length !== b.length) return false;
  const sa = [...a].sort();
  for (let i = 0; i < b.length; i++) if (sa[i] !== b[i]) return false;
  return true;
}

/**
 * Compara las reglas dinámicas existentes de una fuente con las deseadas y
 * devuelve solo lo que cambió. `existing` debe estar filtrado al rango de IDs
 * de la fuente.
 */
export function diffDynamic(
  base: number,
  buckets: number,
  existing: readonly Rule[],
  desired: ReadonlyMap<number, readonly string[]>,
): DynamicDiff {
  const byId = new Map(existing.map((r) => [r.id, r]));
  const removeRuleIds: number[] = [];
  const addRules: Rule[] = [];
  for (let i = 0; i < buckets; i++) {
    const [rid, bid] = bucketRuleIds(base, i);
    const want = desired.get(i);
    const have = byId.get(bid)?.condition.requestDomains;
    const haveRedirect = byId.has(rid);
    if (want && want.length) {
      const sorted = [...want].sort();
      if (sameDomains(have, sorted) && haveRedirect) continue;
      if (byId.has(rid)) removeRuleIds.push(rid);
      if (byId.has(bid)) removeRuleIds.push(bid);
      addRules.push(...rulesForBucket(base, i, sorted));
    } else {
      if (byId.has(rid)) removeRuleIds.push(rid);
      if (byId.has(bid)) removeRuleIds.push(bid);
    }
  }
  return { removeRuleIds, addRules };
}

/** Reconstruye el contenido de los buckets a partir de las reglas "block" existentes. */
export function bucketsFromRules(base: number, buckets: number, rules: readonly Rule[]): Map<number, string[]> {
  const out = new Map<number, string[]>();
  for (const r of rules) {
    const offset = r.id - base;
    if (offset < 0 || offset >= buckets * 2 || offset % 2 !== 1) continue;
    out.set((offset - 1) / 2, [...(r.condition.requestDomains ?? [])]);
  }
  return out;
}

/** Fusiona altas (archivos diarios) en los buckets existentes. Devuelve solo los buckets tocados. */
export function mergeAdditions(
  existing: ReadonlyMap<number, readonly string[]>,
  additions: Iterable<string>,
  buckets: number,
): Map<number, string[]> {
  const touched = new Map<number, Set<string>>();
  for (const d of additions) {
    const b = bucketOf(d, buckets);
    let set = touched.get(b);
    if (!set) {
      set = new Set(existing.get(b) ?? []);
      touched.set(b, set);
    }
    set.add(d);
  }
  const out = new Map<number, string[]>();
  for (const [b, set] of touched) {
    const before = existing.get(b)?.length ?? 0;
    if (set.size !== before) out.set(b, [...set].sort());
  }
  return out;
}

// ---------------------------------------------------------------------------
// Reglas por ruta (una regla por página, solo navegación principal).

/** Primer ID de regla por ruta dentro de un ruleset estático. */
export const STATIC_PATH_BASE = 100_000;
/** Desplazamiento de las reglas por ruta dinámicas respecto de dynamicBase. */
export const DYNAMIC_PATH_OFFSET = 5_000;
export const MAX_DYNAMIC_PATHS = 4_000;

export function pathUrlFilter(path: string): string {
  return `||${path}^`;
}

export function pathRule(id: number, path: string): Rule {
  return {
    id,
    priority: PRIORITY_BLOCK,
    action: {
      type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
      redirect: { extensionPath: BLOCKED_PAGE_PATH },
    },
    condition: {
      urlFilter: pathUrlFilter(path),
      resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
    },
  };
}

export function staticPathRules(paths: readonly string[]): Rule[] {
  return paths.map((p, i) => pathRule(STATIC_PATH_BASE + i, p));
}

/** Ruta original a partir de una regla por ruta. */
export function pathOfRule(r: Rule): string | null {
  const f = r.condition.urlFilter;
  return f && f.startsWith('||') && f.endsWith('^') ? f.slice(2, -1) : null;
}

export interface PathPlan {
  readonly disableStaticRuleIds: number[];
  readonly diff: DynamicDiff;
}

/**
 * Compara rutas actuales con el snapshot estático y con las reglas por ruta
 * dinámicas existentes. Las bajas deshabilitan la regla estática; las altas
 * se agregan como dinámicas reutilizando IDs libres del rango.
 */
export function planPaths(
  staticRules: readonly Rule[],
  existingDynamic: readonly Rule[],
  current: readonly string[],
  dynamicBase: number,
): PathPlan {
  const want = new Set(current);
  const staticPaths = new Set<string>();
  const disableStaticRuleIds: number[] = [];
  for (const r of staticRules) {
    if (r.id < STATIC_PATH_BASE) continue;
    const p = pathOfRule(r);
    if (!p) continue;
    staticPaths.add(p);
    if (!want.has(p)) disableStaticRuleIds.push(r.id);
  }
  const base = dynamicBase + DYNAMIC_PATH_OFFSET;
  const have = new Map<string, number>();
  const removeRuleIds: number[] = [];
  for (const r of existingDynamic) {
    const p = pathOfRule(r);
    if (p && want.has(p) && !staticPaths.has(p) && !have.has(p)) have.set(p, r.id);
    else removeRuleIds.push(r.id);
  }
  const used = new Set(have.values());
  const addRules: Rule[] = [];
  let next = base;
  for (const p of current) {
    if (staticPaths.has(p) || have.has(p)) continue;
    while (used.has(next)) next++;
    if (next >= base + MAX_DYNAMIC_PATHS) break;
    used.add(next);
    addRules.push(pathRule(next, p));
  }
  return { disableStaticRuleIds, diff: { removeRuleIds, addRules } };
}
