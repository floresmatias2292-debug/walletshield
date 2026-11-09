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
import { isExtensionPageSender, parseClipMessage, parseContentRequest, parseFirewallEvent, parsePrivilegedRequest } from '../shared/messages';
import { contentConfig } from '../shared/settings';
import { simulate } from './simulation';
import { SOURCE_IDS } from './lists/sources';
import { getSourceState } from './state';

// El almacenamiento local (ajustes, registro de eventos, API key) solo es
// accesible para páginas de la extensión y el worker, nunca para content
// scripts. Lo que estos necesitan lo piden por mensaje ("cs:config").
void chrome.storage.local.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' }).catch(() => undefined);

const SECRET_KEY = 'secret:tenderlyKey';

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
  // Las pestañas abiertas vuelven a pedir su configuración (sin esperar a recargar).
  void chrome.tabs.query({}).then((tabs) => {
    for (const t of tabs) if (t.id !== undefined) void chrome.tabs.sendMessage(t.id, { type: 'cs:invalidate' }).catch(() => undefined);
  });
});

// Mensajes de content scripts (no confiables): solo eventos del firewall,
// validados y con límite de frecuencia por pestaña.
const fwRate = new Map<number, { t: number; n: number }>();
const simRate = new Map<number, { t: number; n: number }>();
chrome.runtime.onMessage.addListener((raw: unknown, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !sender.tab?.id || isExtensionPageSender(sender, chrome.runtime.id)) return false;
  const clip = parseClipMessage(raw);
  if (clip) {
    // Última dirección copiada: solo en storage.session (memoria, no accesible a content scripts).
    if (clip.type === 'clip:copy') {
      void getSettings().then((s) => (s.clipboardGuard ? chrome.storage.session.set({ lastCopied: { address: clip.address, t: Date.now() } }) : undefined));
      return false;
    }
    void (async () => {
      const s = await getSettings();
      const r = await chrome.storage.session.get('lastCopied');
      sendResponse({ enabled: s.clipboardGuard, lastCopied: s.clipboardGuard ? (r.lastCopied ?? null) : null });
    })();
    return true;
  }
  const req = parseContentRequest(raw);
  if (req) {
    const tabId = sender.tab.id;
    void (async () => {
      const s = await getSettings();
      if (req.type === 'cs:config') {
        const { badAddresses } = await chrome.storage.local.get('badAddresses');
        return sendResponse({ config: contentConfig(s), badAddresses: Array.isArray(badAddresses) ? badAddresses : [] });
      }
      // Simulación: solo si el usuario la activó y cargó su key; máx. 10 por minuto por pestaña.
      const key = (await chrome.storage.local.get(SECRET_KEY))[SECRET_KEY];
      if (!s.simulation.enabled || typeof key !== 'string' || !key) return sendResponse({ ok: false, error: 'simulación desactivada' });
      const now = Date.now();
      const r = simRate.get(tabId);
      if (r && now - r.t < 60_000 && ++r.n > 10) return sendResponse({ ok: false, error: 'demasiadas simulaciones' });
      if (!r || now - r.t >= 60_000) simRate.set(tabId, { t: now, n: 1 });
      return sendResponse(await simulate({ account: s.simulation.account, project: s.simulation.project, key }, req.chainId, req.blockNumber, req.tx));
    })();
    return true;
  }
  const ev = parseFirewallEvent(raw);
  if (!ev) return false;
  const now = Date.now();
  const r = fwRate.get(sender.tab.id);
  if (r && now - r.t < 60_000) {
    if (++r.n > 30) return false;
  } else fwRate.set(sender.tab.id, { t: now, n: 1 });
  const tabId = sender.tab.id;
  void (async () => {
    if (ev.kind === 'fw-threat' && ev.risk === 'high') {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#c62828' });
      await chrome.action.setBadgeText({ tabId, text: '!' });
      await chrome.action.setTitle({ tabId, title: `WalletShield: comportamiento sospechoso en ${ev.host}` });
    }
    if (ev.kind === 'fw-block' || ev.kind === 'fw-auto-block') await bumpBlocked();
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
        const sources: Record<string, unknown> = {};
        for (const id of SOURCE_IDS) {
          const st = await getSourceState(id);
          sources[id] = { count: st.count ?? null, lastSync: st.lastSync ?? null, error: st.error ?? null };
        }
        return sendResponse({ settings, stats: stats ?? null, events: events ?? [], sources });
      }
      case 'lists:sync':
        return sendResponse(await syncAll());
      case 'events:clear':
        await chrome.storage.local.set({ events: [] });
        return sendResponse({ ok: true });
      case 'secret:set':
        if (msg.key) await chrome.storage.local.set({ [SECRET_KEY]: msg.key });
        else await chrome.storage.local.remove(SECRET_KEY);
        return sendResponse({ ok: true });
      case 'secret:status': {
        const k = (await chrome.storage.local.get(SECRET_KEY))[SECRET_KEY];
        return sendResponse({ hasKey: typeof k === 'string' && k.length > 0 });
      }
    }
  })();
  return true; // respuesta asíncrona
});
