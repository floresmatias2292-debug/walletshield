/** Acceso a estado y ajustes desde páginas de la extensión (popup y opciones). */
import { parseSettings, type Settings } from '../shared/settings';
import type { LogEvent, Stats } from '../background/state';

export interface SourceStatus {
  readonly count: number | null;
  readonly lastSync: number | null;
  readonly error: string | null;
}

export interface UiState {
  readonly settings: Settings;
  readonly stats: Stats | null;
  readonly events: readonly LogEvent[];
  readonly sources: Readonly<Record<string, SourceStatus>>;
}

export async function loadState(): Promise<UiState> {
  const r = (await chrome.runtime.sendMessage({ type: 'state:get' })) as Partial<UiState> | null;
  return {
    settings: parseSettings(r?.settings),
    stats: r?.stats ?? null,
    events: Array.isArray(r?.events) ? r.events : [],
    sources: r?.sources ?? {},
  };
}

/** Aplica un cambio a los ajustes (siempre validado con parseSettings). */
export async function updateSettings(change: (s: Settings) => Settings): Promise<Settings> {
  const { settings } = await chrome.storage.local.get('settings');
  const next = parseSettings(change(parseSettings(settings)));
  await chrome.storage.local.set({ settings: next });
  return next;
}

export function todayCount(stats: Stats | null): number {
  if (!stats) return 0;
  return stats.day === new Date().toISOString().slice(0, 10) ? stats.blockedToday : 0;
}

export function ago(t: number | null): string {
  if (!t) return 'nunca';
  const m = Math.round((Date.now() - t) / 60000);
  if (m < 1) return 'hace instantes';
  if (m < 60) return `hace ${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `hace ${h} h`;
  return `hace ${Math.round(h / 24)} días`;
}

/** Crea un elemento con texto (nunca innerHTML). */
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, string> = {}, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

export function $(id: string): HTMLElement {
  const e = document.getElementById(id);
  if (!e) throw new Error(`falta #${id}`);
  return e;
}

export const EVENT_LABEL: Record<string, string> = {
  'list-block': 'Sitio bloqueado (lista)',
  'heuristic-block': 'Sitio bloqueado (imitación)',
  'heuristic-warn': 'Aviso de imitación',
  proceed: 'Continuaste a un sitio bloqueado',
  'lists-updated': 'Listas actualizadas',
  error: 'Error',
  'fw-block': 'Firma bloqueada',
  'fw-allow': 'Firma permitida tras aviso',
  'fw-auto-block': 'Firma bloqueada automáticamente',
  'fw-threat': 'Comportamiento sospechoso',
};
