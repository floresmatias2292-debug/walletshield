/**
 * Service worker de WalletShield (Manifest V3).
 *
 * Todo es event-driven: no hay setInterval ni polling. Los listeners se
 * registran en el nivel superior para que Chrome pueda despertar al worker,
 * y el worker vuelve a dormir cuando no hay eventos.
 */
import { syncAll, writeUpstreamAllowRule, writeUserAllowRule, addSessionAllow } from './lists/dnr-sync';
import { allowForSession, blockedContextFor, forgetTab, onBeforeNavigate } from './navigation-guard';
import { bumpBlocked, getSettings, logEvent } from './state';
import { isExtensionPageSender, parseFirewallEvent, parsePrivilegedRequest } from '../shared/messages';

const ALARM = 'lists-update';
const PERIOD_MIN = 6 * 60;

async function ensureAlarm(): Promise<void> {
  const existing = await chrome.alarms.get(ALARM);
  if (!existing) await chrome.alarms.create(ALARM, { periodInMinutes: PERIOD_MIN, delayInMinutes: PERIOD_MIN });
}

async function loadSnapshotAllow(): Promise<string[]> {
  const res = await fetch(chrome.runtime.getURL('rules/static/meta.json'));
  const meta = (await res.json()) as { upstreamAllow?: unknown };
  return Array.isArray(meta.upstreamAllow) ? meta.upstreamAllow.filter((x): x is string => typeof x === 'string') : [];
}

chrome.runtime.onInstalled.addListener((details) => {
  void (async () => {
    await writeUpstreamAllowRule(await loadSnapshotAllow());
    await writeUserAllowRule();
    await ensureAlarm();
    // Instalación o actualización: el snapshot estático ya protege; se baja el diff.
    await syncAll({ force: details.reason === 'update' });
  })();
});

chrome.runtime.onStartup.addListener(() => {
  void ensureAlarm();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) void syncAll();
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  void onBeforeNavigate(details).catch((e: unknown) =>
    logEvent({ kind: 'error', detail: `navegación: ${e instanceof Error ? e.message : String(e)}` }),
  );
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void forgetTab(tabId);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.settings) return;
  const before = changes.settings.oldValue as { sources?: unknown; allowlist?: unknown } | undefined;
  const after = changes.settings.newValue as { sources?: unknown; allowlist?: unknown } | undefined;
  if (JSON.stringify(before?.allowlist) !== JSON.stringify(after?.allowlist)) void writeUserAllowRule();
  if (JSON.stringify(before?.sources) !== JSON.stringify(after?.sources)) void syncAll();
});

// Mensajes de content scripts (no confiables): solo eventos del firewall,
// validados y con límite de frecuencia por pestaña.
const fwRate = new Map<number, { t: number; n: number }>();
chrome.runtime.onMessage.addListener((raw: unknown, sender) => {
  if (sender.id !== chrome.runtime.id || !sender.tab?.id || isExtensionPageSender(sender, chrome.runtime.id)) return false;
  const ev = parseFirewallEvent(raw);
  if (!ev) return false;
  const now = Date.now();
  const r = fwRate.get(sender.tab.id);
  if (r && now - r.t < 60_000) {
    if (++r.n > 30) return false;
  } else fwRate.set(sender.tab.id, { t: now, n: 1 });
  void (async () => {
    if (ev.kind !== 'fw-allow') await bumpBlocked();
    await logEvent({ kind: ev.kind, host: ev.host, detail: `${ev.method} · ${ev.risk} · ${ev.codes.join(',')}` });
  })();
  return false;
});

chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse) => {
  // Solo páginas propias de la extensión pueden usar estos mensajes; los
  // content scripts (que corren en páginas web) quedan excluidos.
  if (!isExtensionPageSender(sender, chrome.runtime.id)) return false;
  const msg = parsePrivilegedRequest(raw);
  if (!msg) return false;

  void (async () => {
    switch (msg.type) {
      case 'blocked:context': {
        const tabId = sender.tab?.id;
        if (tabId === undefined) return sendResponse(null);
        const ctx = await blockedContextFor(tabId);
        if (ctx.kind === 'list') {
          await bumpBlocked();
          await logEvent({ kind: 'list-block', ...(ctx.host ? { host: ctx.host } : {}) });
        }
        return sendResponse(ctx);
      }
      case 'blocked:proceed': {
        const tabId = sender.tab?.id;
        if (tabId === undefined) return sendResponse({ ok: false });
        // El host debe ser exactamente el que se bloqueó en ESA pestaña: una
        // página no puede pedir que se desbloquee un dominio arbitrario.
        const ctx = await blockedContextFor(tabId);
        if (!ctx.host || !ctx.url || ctx.host !== msg.host) return sendResponse({ ok: false });
        await addSessionAllow(ctx.host);
        await allowForSession(ctx.host);
        await logEvent({ kind: 'proceed', host: ctx.host });
        await chrome.tabs.update(tabId, { url: ctx.url });
        return sendResponse({ ok: true });
      }
      case 'state:get': {
        const settings = await getSettings();
        const { stats, events } = await chrome.storage.local.get(['stats', 'events']);
        return sendResponse({ settings, stats: stats ?? null, events: events ?? [] });
      }
    }
  })();
  return true; // respuesta asíncrona
});
