/**
 * Sincroniza las listas descargadas con las reglas declarativeNetRequest.
 * Solo corre por alarma (cada 6 h), al instalar o al cambiar ajustes.
 */
import { conditionalFetchJson } from './fetcher';
import { PARSERS } from './parsers';
import { sanitizeAll, sanitizePaths, upstreamAllowDomains, type AllowLists } from './sanitize';
import {
  bucketize,
  bucketsFromRules,
  bucketRuleIds,
  diffDynamic,
  DYNAMIC_PATH_OFFSET,
  MAX_DYNAMIC_PATHS,
  mergeAdditions,
  planPaths,
  planSource,
  type DynamicDiff,
} from './buckets';
import {
  PRIORITY_UPSTREAM_ALLOW,
  PRIORITY_USER_ALLOW,
  RULE_ID_UPSTREAM_ALLOW,
  RULE_ID_USER_ALLOW,
  SOURCES,
  SOURCE_IDS,
  type SourceDef,
  type SourceId,
} from './sources';
import { getSettings, getSourceState, logEvent, setSourceState, today } from '../state';

type Rule = chrome.declarativeNetRequest.Rule;
const DNR = chrome.declarativeNetRequest;

const FULL_REFRESH_MS = 7 * 24 * 3600 * 1000; // ScamSniffer: lista completa 1 vez por semana
const MAX_ARCHIVE_DAYS = 14;
const ADD_BATCH = 100;

const FRAME_TYPES = ['main_frame', 'sub_frame'] as chrome.declarativeNetRequest.ResourceType[];
const ALL_TYPES = [
  'main_frame', 'sub_frame', 'script', 'xmlhttprequest', 'websocket',
] as chrome.declarativeNetRequest.ResourceType[];

// Serializa las sincronizaciones dentro de la vida del worker.
let chain: Promise<unknown> = Promise.resolve();
function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const next = chain.then(fn, fn);
  chain = next.catch(() => undefined);
  return next;
}

async function getUpstreamAllow(): Promise<string[]> {
  const { upstreamAllow } = await chrome.storage.local.get('upstreamAllow');
  return Array.isArray(upstreamAllow) ? (upstreamAllow as string[]) : [];
}

/** Regla 2: dominios legítimos + whitelist de MetaMask nunca se bloquean. */
export async function writeUpstreamAllowRule(extra?: readonly string[]): Promise<void> {
  const list = extra ?? (await getUpstreamAllow());
  await chrome.storage.local.set({ upstreamAllow: [...list] });
  await DNR.updateDynamicRules({
    removeRuleIds: [RULE_ID_UPSTREAM_ALLOW],
    addRules: [
      {
        id: RULE_ID_UPSTREAM_ALLOW,
        priority: PRIORITY_UPSTREAM_ALLOW,
        action: { type: 'allow' as chrome.declarativeNetRequest.RuleActionType },
        condition: { requestDomains: upstreamAllowDomains(list), resourceTypes: ALL_TYPES },
      },
    ],
  });
}

/** Regla 1: sitios de confianza del usuario (solo navegación, no subrecursos). */
export async function writeUserAllowRule(): Promise<void> {
  const { allowlist } = await getSettings();
  const addRules: Rule[] = allowlist.length
    ? [
        {
          id: RULE_ID_USER_ALLOW,
          priority: PRIORITY_USER_ALLOW,
          action: { type: 'allow' as chrome.declarativeNetRequest.RuleActionType },
          condition: { requestDomains: [...allowlist], resourceTypes: FRAME_TYPES },
        },
      ]
    : [];
  await DNR.updateDynamicRules({ removeRuleIds: [RULE_ID_USER_ALLOW], addRules });
}

/** Permite un host solo hasta que se cierre el navegador ("Continuar de todos modos"). */
export async function addSessionAllow(host: string): Promise<void> {
  const existing = await DNR.getSessionRules();
  if (existing.some((r) => r.condition.requestDomains?.includes(host))) return;
  const id = existing.reduce((m, r) => Math.max(m, r.id), 0) + 1;
  await DNR.updateSessionRules({
    addRules: [
      {
        id,
        priority: PRIORITY_USER_ALLOW,
        action: { type: 'allow' as chrome.declarativeNetRequest.RuleActionType },
        condition: { requestDomains: [host], resourceTypes: FRAME_TYPES },
      },
    ],
  });
}

async function dynamicRulesOf(src: SourceDef): Promise<Rule[]> {
  const all = await DNR.getDynamicRules();
  return all.filter((r) => r.id >= src.dynamicBase && r.id < src.dynamicBase + src.buckets * 2);
}

async function dynamicPathRulesOf(src: SourceDef): Promise<Rule[]> {
  const lo = src.dynamicBase + DYNAMIC_PATH_OFFSET;
  const all = await DNR.getDynamicRules();
  return all.filter((r) => r.id >= lo && r.id < lo + MAX_DYNAMIC_PATHS);
}

async function applyDiff(diff: DynamicDiff): Promise<void> {
  const addIds = new Set(diff.addRules.map((r) => r.id));
  const removeSet = new Set(diff.removeRuleIds);
  const pureRemovals = diff.removeRuleIds.filter((id) => !addIds.has(id));
  for (let i = 0; i < pureRemovals.length; i += 1000) {
    await DNR.updateDynamicRules({ removeRuleIds: pureRemovals.slice(i, i + 1000) });
  }
  for (let i = 0; i < diff.addRules.length; i += ADD_BATCH) {
    const chunk = diff.addRules.slice(i, i + ADD_BATCH);
    await DNR.updateDynamicRules({
      removeRuleIds: chunk.map((r) => r.id).filter((id) => removeSet.has(id)),
      addRules: chunk,
    });
  }
}

async function loadSnapshotRules(src: SourceDef): Promise<Rule[]> {
  if (!src.staticRuleset) return [];
  const res = await fetch(chrome.runtime.getURL(`rules/static/${src.staticRuleset}.json`));
  return (await res.json()) as Rule[];
}

function snapshotBuckets(src: SourceDef, rules: readonly Rule[]): string[][] | null {
  if (!src.staticRuleset) return null;
  const map = bucketsFromRules(1, src.buckets, rules);
  return Array.from({ length: src.buckets }, (_, i) => map.get(i) ?? []);
}

async function setStaticDisabled(src: SourceDef, desired: readonly number[]): Promise<void> {
  if (!src.staticRuleset) return;
  const rulesetId = src.staticRuleset;
  const current = await DNR.getDisabledRuleIds({ rulesetId });
  const want = new Set(desired);
  const have = new Set(current);
  const disableRuleIds = desired.filter((id) => !have.has(id));
  const enableRuleIds = current.filter((id) => !want.has(id));
  if (disableRuleIds.length || enableRuleIds.length) {
    await DNR.updateStaticRules({ rulesetId, disableRuleIds, enableRuleIds });
  }
}

async function setSourceEnabled(src: SourceDef, enabled: boolean): Promise<void> {
  if (src.staticRuleset) {
    const on = await DNR.getEnabledRulesets();
    const isOn = on.includes(src.staticRuleset);
    if (enabled && !isOn) await DNR.updateEnabledRulesets({ enableRulesetIds: [src.staticRuleset] });
    if (!enabled && isOn) await DNR.updateEnabledRulesets({ disableRulesetIds: [src.staticRuleset] });
  }
  if (!enabled) {
    const existing = [...(await dynamicRulesOf(src)), ...(await dynamicPathRulesOf(src))];
    await applyDiff({ removeRuleIds: existing.map((r) => r.id), addRules: [] });
  }
}

async function fullSync(src: SourceDef): Promise<'not-modified' | number> {
  const state = await getSourceState(src.id);
  const res = await conditionalFetchJson(src.url, state.meta);
  if (res.status === 'not-modified') return 'not-modified';
  if (res.status === 'not-found') throw new Error(`${src.id}: lista no encontrada`);

  const parsed = PARSERS[src.id](res.json);
  if (src.id === 'metamask') await writeUpstreamAllowRule(parsed.allowWithSubdomains);
  const allow: AllowLists = {
    exact: new Set(parsed.allowExact),
    withSubdomains: new Set([...parsed.allowWithSubdomains, ...(await getUpstreamAllow())]),
  };
  const domains = sanitizeAll(parsed.block, allow);
  // Defensa contra listas truncadas o envenenadas: no aceptar un colapso brusco.
  if (state.count && domains.length < state.count * 0.5) {
    throw new Error(`${src.id}: la lista bajó de ${state.count} a ${domains.length}, se ignora`);
  }
  const buckets = bucketize(domains, src.buckets);
  const snapshotRules = await loadSnapshotRules(src);
  const plan = planSource(snapshotBuckets(src, snapshotRules), buckets);
  const paths = sanitizePaths([...parsed.block, ...parsed.blockPaths]);
  const pathPlan = planPaths(snapshotRules, await dynamicPathRulesOf(src), paths, src.dynamicBase);
  await setStaticDisabled(src, [...plan.disableStaticRuleIds, ...pathPlan.disableStaticRuleIds]);
  await applyDiff(diffDynamic(src.dynamicBase, src.buckets, await dynamicRulesOf(src), plan.dynamicBuckets));
  await applyDiff(pathPlan.diff);

  const now = Date.now();
  const { error: _prevError, ...rest } = state;
  await setSourceState(src.id, {
    ...rest,
    meta: res.meta,
    lastSync: now,
    lastFull: now,
    count: domains.length,
    // los archivos diarios se publican con ~7 días de demora
    ...(src.archiveUrl ? { archiveCursor: today(now - 8 * 24 * 3600 * 1000) } : {}),
  });
  return domains.length;
}

function nextDay(d: string): string {
  const t = new Date(`${d}T00:00:00Z`).getTime() + 24 * 3600 * 1000;
  return today(t);
}

/** Solo altas: descarga los archivos diarios posteriores al cursor. */
async function incrementalSync(src: SourceDef): Promise<number> {
  const state = await getSourceState(src.id);
  if (!src.archiveUrl || !state.archiveCursor) return 0;
  const additions: unknown[] = [];
  let cursor = state.archiveCursor;
  const end = today();
  for (let i = 0; i < MAX_ARCHIVE_DAYS && cursor < end; i++) {
    const day = nextDay(cursor);
    const res = await conditionalFetchJson(src.archiveUrl(day), undefined);
    if (res.status === 'not-found') break; // todavía no publicado
    if (res.status === 'ok') for (const d of PARSERS[src.id](res.json).block) additions.push(d);
    cursor = day;
  }
  const clean = sanitizeAll(additions, { exact: new Set(), withSubdomains: new Set(await getUpstreamAllow()) });
  if (clean.length) {
    const blockIds = Array.from({ length: src.buckets }, (_, i) => bucketRuleIds(src.dynamicBase, i)[1]);
    const existing = bucketsFromRules(src.dynamicBase, src.buckets, await DNR.getDynamicRules({ ruleIds: blockIds }));
    const touched = mergeAdditions(existing, clean, src.buckets);
    if (touched.size) {
      const touchedIds = [...touched.keys()].flatMap((b) => bucketRuleIds(src.dynamicBase, b));
      const touchedRules = await DNR.getDynamicRules({ ruleIds: touchedIds });
      // Solo se pasan los buckets tocados: los demás no se modifican.
      await applyDiff(diffDynamic(src.dynamicBase, src.buckets, touchedRules, touched));
    }
  }
  const { error: _prevError, ...rest } = state;
  await setSourceState(src.id, {
    ...rest,
    archiveCursor: cursor,
    lastSync: Date.now(),
    count: (state.count ?? 0) + clean.length,
  });
  return clean.length;
}

export interface SyncReport {
  readonly source: SourceId;
  readonly result: string;
}

export function syncAll(opts: { force?: boolean } = {}): Promise<SyncReport[]> {
  return serialized(async () => {
    const settings = await getSettings();
    const reports: SyncReport[] = [];
    for (const id of SOURCE_IDS) {
      const src = SOURCES[id];
      const enabled = settings.sources[id];
      try {
        await setSourceEnabled(src, enabled);
        if (!enabled) {
          reports.push({ source: id, result: 'desactivada' });
          continue;
        }
        const state = await getSourceState(id);
        const needFull =
          opts.force || !src.archiveUrl || !state.lastFull || Date.now() - state.lastFull > FULL_REFRESH_MS;
        if (opts.force) await setSourceState(id, { ...state, meta: {} });
        const r = needFull ? await fullSync(src) : `+${await incrementalSync(src)}`;
        reports.push({ source: id, result: String(r) });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const state = await getSourceState(id);
        await setSourceState(id, { ...state, error: msg });
        await logEvent({ kind: 'error', detail: `${id}: ${msg}` });
        reports.push({ source: id, result: `error: ${msg}` });
      }
    }
    await logEvent({ kind: 'lists-updated', detail: reports.map((r) => `${r.source}=${r.result}`).join(' ') });
    return reports;
  });
}
