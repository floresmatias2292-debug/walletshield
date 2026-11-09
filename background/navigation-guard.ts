/**
 * Vigilancia de navegación: cada navegación principal se analiza con las
 * heurísticas de dominio (homoglifos, typosquatting, combos de marca).
 * El bloqueo por listas lo hace el motor DNR; aquí solo se cubre lo que
 * las listas todavía no conocen.
 */
import { DomainAnalyzer, type DomainVerdict } from '../shared/domain/typosquat';
import { hostAndParents, hostnameFromUrl, registrableDomain } from '../shared/domain/normalize';
import { domainInterstitialThreshold, riskAtLeast, type RiskLevel } from '../shared/risk';
import type { BlockedContext } from '../shared/messages';
import { BLOCKED_PAGE_PATH } from './lists/sources';
import { bumpBlocked, getSettings, logEvent } from './state';
import { domainAgeDays } from './rdap';

const analyzer = new DomainAnalyzer();
const NEW_DOMAIN_DAYS = 30;

interface NavContext {
  url: string;
  host: string;
  verdict: DomainVerdict | null;
  heuristicRedirect: boolean;
}

// Caché en memoria (el worker puede dormir: se respalda en storage.session).
const navByTab = new Map<number, NavContext>();

async function saveNav(tabId: number, ctx: NavContext): Promise<void> {
  navByTab.set(tabId, ctx);
  await chrome.storage.session.set({ [`nav:${tabId}`]: ctx });
}

export async function getNav(tabId: number): Promise<NavContext | null> {
  const mem = navByTab.get(tabId);
  if (mem) return mem;
  const key = `nav:${tabId}`;
  const r = await chrome.storage.session.get(key);
  return (r[key] as NavContext | undefined) ?? null;
}

export async function forgetTab(tabId: number): Promise<void> {
  navByTab.delete(tabId);
  await chrome.storage.session.remove(`nav:${tabId}`);
}

function matchesList(host: string, list: Iterable<string>): boolean {
  const set = list instanceof Set ? (list as Set<string>) : new Set(list);
  for (const p of hostAndParents(host)) if (set.has(p)) return true;
  return false;
}

async function sessionAllowed(): Promise<Set<string>> {
  const { sessionAllow } = await chrome.storage.session.get('sessionAllow');
  return new Set(Array.isArray(sessionAllow) ? (sessionAllow as string[]) : []);
}

export async function allowForSession(host: string): Promise<void> {
  const s = await sessionAllowed();
  s.add(host);
  await chrome.storage.session.set({ sessionAllow: [...s] });
}

export async function isTrusted(host: string): Promise<boolean> {
  const settings = await getSettings();
  if (matchesList(host, settings.allowlist)) return true;
  if (matchesList(host, await sessionAllowed())) return true;
  const { upstreamAllow } = await chrome.storage.local.get('upstreamAllow');
  return Array.isArray(upstreamAllow) && matchesList(host, upstreamAllow as string[]);
}

export async function onBeforeNavigate(details: chrome.webNavigation.WebNavigationBaseCallbackDetails): Promise<void> {
  if (details.frameId !== 0 || details.tabId < 0) return;
  const host = hostnameFromUrl(details.url);
  if (!host) return; // páginas internas, la propia página de bloqueo, IPs, etc.

  const ctx: NavContext = { url: details.url, host, verdict: null, heuristicRedirect: false };
  navByTab.set(details.tabId, ctx);
  void chrome.action.setBadgeText({ tabId: details.tabId, text: '' }).catch(() => undefined);

  if (await isTrusted(host)) {
    await saveNav(details.tabId, ctx);
    return;
  }
  const settings = await getSettings();
  let verdict = analyzer.analyze(host);
  let risk: RiskLevel = verdict.risk;

  // Escalado opcional: dominio sospechoso + registrado hace menos de 30 días.
  if (settings.rdapLookup && risk === 'medium') {
    const age = await domainAgeDays(registrableDomain(host));
    if (age !== null && age < NEW_DOMAIN_DAYS) {
      risk = 'high';
      verdict = { ...verdict, risk, reasons: [...verdict.reasons, { code: 'new-domain', risk: 'high' }] };
    }
  }
  ctx.verdict = verdict.risk === 'none' ? null : verdict;

  const threshold = domainInterstitialThreshold(settings.strictness);
  if (risk !== 'none' && riskAtLeast(risk, threshold)) {
    ctx.heuristicRedirect = true;
    await saveNav(details.tabId, ctx);
    await chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL(`${BLOCKED_PAGE_PATH}?src=h`),
    });
    await bumpBlocked();
    await logEvent({ kind: 'heuristic-block', host, detail: verdict.reasons.map((r) => r.code).join(',') });
    return;
  }
  await saveNav(details.tabId, ctx);
  if (riskAtLeast(risk, 'medium') || (settings.strictness === 'strict' && risk === 'low')) {
    await chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: '#d97706' });
    await chrome.action.setBadgeText({ tabId: details.tabId, text: '!' });
    await chrome.action.setTitle({ tabId: details.tabId, title: `WalletShield: ${host} parece imitar otro sitio` });
    await logEvent({ kind: 'heuristic-warn', host, detail: verdict.reasons.map((r) => r.code).join(',') });
  }
}

export async function blockedContextFor(tabId: number): Promise<BlockedContext> {
  const nav = await getNav(tabId);
  return {
    url: nav?.url ?? null,
    host: nav?.host ?? null,
    kind: nav?.heuristicRedirect ? 'heuristic' : 'list',
    risk: nav?.heuristicRedirect ? (nav.verdict?.risk ?? 'high') : 'high',
    reasons: nav?.verdict?.reasons ?? [],
  };
}
