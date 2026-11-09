/**
 * Estado persistente del service worker. Todo vive en chrome.storage (el
 * worker puede morir en cualquier momento); en memoria solo hay cachés que
 * se reconstruyen al despertar.
 */
import { DEFAULT_SETTINGS, parseSettings, type Settings } from '../shared/settings';
import type { SourceId } from './lists/sources';
import type { FetchMeta } from './lists/fetcher';

export interface SourceState {
  meta?: FetchMeta;
  lastSync?: number;
  lastFull?: number;
  /** Último archivo diario aplicado (YYYY-MM-DD), solo ScamSniffer. */
  archiveCursor?: string;
  count?: number;
  error?: string;
}

export interface Stats {
  day: string;
  blockedToday: number;
  blockedTotal: number;
}

export type EventKind =
  | 'list-block' | 'heuristic-block' | 'heuristic-warn' | 'proceed' | 'lists-updated' | 'error'
  | 'fw-block' | 'fw-allow' | 'fw-auto-block' | 'fw-threat';

export interface LogEvent {
  t: number;
  kind: EventKind;
  host?: string;
  detail?: string;
}

const MAX_EVENTS = 300;

let settingsCache: Settings | null = null;

export async function getSettings(): Promise<Settings> {
  if (settingsCache) return settingsCache;
  const { settings } = await chrome.storage.local.get('settings');
  settingsCache = parseSettings(settings ?? DEFAULT_SETTINGS);
  return settingsCache;
}

export async function saveSettings(s: Settings): Promise<void> {
  settingsCache = parseSettings(s);
  await chrome.storage.local.set({ settings: settingsCache });
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.settings) settingsCache = null;
});

export async function getSourceState(id: SourceId): Promise<SourceState> {
  const key = `source:${id}`;
  const r = await chrome.storage.local.get(key);
  return (r[key] as SourceState | undefined) ?? {};
}

export async function setSourceState(id: SourceId, s: SourceState): Promise<void> {
  await chrome.storage.local.set({ [`source:${id}`]: s });
}

export function today(now = Date.now()): string {
  return new Date(now).toISOString().slice(0, 10);
}

export async function bumpBlocked(): Promise<void> {
  const { stats } = await chrome.storage.local.get('stats');
  const s = (stats as Stats | undefined) ?? { day: today(), blockedToday: 0, blockedTotal: 0 };
  const d = today();
  const next: Stats = {
    day: d,
    blockedToday: (s.day === d ? s.blockedToday : 0) + 1,
    blockedTotal: s.blockedTotal + 1,
  };
  await chrome.storage.local.set({ stats: next });
}

export async function logEvent(e: Omit<LogEvent, 't'>): Promise<void> {
  const { events } = await chrome.storage.local.get('events');
  const list = Array.isArray(events) ? (events as LogEvent[]) : [];
  list.push({ t: Date.now(), ...e });
  if (list.length > MAX_EVENTS) list.splice(0, list.length - MAX_EVENTS);
  await chrome.storage.local.set({ events: list });
}
