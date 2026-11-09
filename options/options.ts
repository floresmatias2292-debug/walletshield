import { normalizeHost } from '../shared/domain/normalize';
import { hostToUnicode } from '../shared/domain/punycode';
import { exportSettings, importSettings, MAX_ALLOWLIST, parseSettings, type Settings } from '../shared/settings';
import type { Strictness } from '../shared/risk';
import { $, ago, el, EVENT_LABEL, loadState, todayCount, updateSettings, type UiState } from '../ui/store';

const SOURCE_NAMES: Record<string, string> = {
  metamask: 'MetaMask eth-phishing-detect',
  polkadot: 'polkadot-js/phishing',
  scamsniffer: 'ScamSniffer (+ direcciones de drainers)',
};
const SLUG = /^[A-Za-z0-9_.-]{1,64}$/;

function msg(id: string, text: string, ok = true): void {
  const e = $(id);
  e.textContent = text;
  e.className = `small ${ok ? 'ok-text' : 'err-text'}`;
}

async function save(change: (s: Settings) => Settings): Promise<void> {
  await updateSettings(change);
  await refresh();
}

function renderSources(state: UiState): void {
  const ul = $('sources');
  ul.replaceChildren();
  for (const id of ['metamask', 'polkadot', 'scamsniffer'] as const) {
    const st = state.sources[id];
    const li = el('li');
    const left = el('div');
    left.append(el('div', {}, SOURCE_NAMES[id] ?? id));
    const info = st?.error
      ? `Error: ${st.error}`
      : st?.count
        ? `${st.count.toLocaleString('es-AR')} dominios · actualizada ${ago(st.lastSync)}`
        : `actualizada ${ago(st?.lastSync ?? null)}`;
    left.append(el('div', { class: `small ${st?.error ? 'err-text' : 'muted'}` }, info));
    const cb = el('input', { type: 'checkbox', 'aria-label': `Activar ${SOURCE_NAMES[id]}` }) as HTMLInputElement;
    cb.checked = state.settings.sources[id];
    cb.addEventListener('change', () => void save((s) => ({ ...s, sources: { ...s.sources, [id]: cb.checked } })));
    li.append(left, cb);
    ul.append(li);
  }
}

function renderAllow(s: Settings): void {
  const ul = $('allow');
  ul.replaceChildren();
  if (!s.allowlist.length) ul.append(el('li', { class: 'muted small' }, 'Sin sitios de confianza.'));
  for (const h of s.allowlist) {
    const li = el('li');
    const x = el('button', { class: 'x', type: 'button', title: 'Quitar', 'aria-label': `Quitar ${h}` }, '×');
    x.addEventListener('click', () => void save((cur) => ({ ...cur, allowlist: cur.allowlist.filter((a) => a !== h) })));
    li.append(el('span', { class: 'mono' }, hostToUnicode(h)), x);
    ul.append(li);
  }
}

const FILTERS: Record<string, (k: string) => boolean> = {
  '': () => true,
  block: (k) => k.includes('block'),
  threat: (k) => k === 'fw-threat' || k === 'heuristic-warn',
  lists: (k) => k === 'lists-updated',
  error: (k) => k === 'error',
};

function renderLog(state: UiState): void {
  const f = FILTERS[($('filter') as HTMLSelectElement).value] ?? FILTERS[''];
  const tbody = $('log');
  tbody.replaceChildren();
  const rows = [...state.events].reverse().filter((e) => f!(e.kind)).slice(0, 300);
  if (!rows.length) {
    const tr = el('tr');
    tr.append(el('td', { colspan: '4', class: 'muted' }, 'Sin eventos.'));
    tbody.append(tr);
  }
  for (const e of rows) {
    const tr = el('tr');
    tr.append(
      el('td', {}, new Date(e.t).toLocaleString('es-AR')),
      el('td', {}, EVENT_LABEL[e.kind] ?? e.kind),
      el('td', { class: 'mono' }, e.host ? hostToUnicode(e.host) : '—'),
      el('td', {}, (e.detail ?? '').slice(0, 300)),
    );
    tbody.append(tr);
  }
  $('statsLine').textContent = `Amenazas bloqueadas hoy: ${todayCount(state.stats)} · en total: ${state.stats?.blockedTotal ?? 0}`;
}

let lastState: UiState | null = null;
async function refresh(): Promise<void> {
  const state = await loadState();
  lastState = state;
  const s = state.settings;
  for (const r of document.querySelectorAll<HTMLInputElement>('input[name=level]')) r.checked = r.value === s.strictness;
  ($('firewall') as HTMLInputElement).checked = s.firewall;
  ($('clipboard') as HTMLInputElement).checked = s.clipboardGuard;
  ($('rdap') as HTMLInputElement).checked = s.rdapLookup;
  ($('simEnabled') as HTMLInputElement).checked = s.simulation.enabled;
  const acc = $('simAccount') as HTMLInputElement;
  const proj = $('simProject') as HTMLInputElement;
  if (document.activeElement !== acc) acc.value = s.simulation.account;
  if (document.activeElement !== proj) proj.value = s.simulation.project;
  renderSources(state);
  renderAllow(s);
  renderLog(state);
}

async function main(): Promise<void> {
  await refresh();
  const st = (await chrome.runtime.sendMessage({ type: 'secret:status' })) as { hasKey?: boolean } | null;
  ($('simKey') as HTMLInputElement).placeholder = st?.hasKey ? 'key guardada (escribe para reemplazarla)' : 'sin key';

  for (const r of document.querySelectorAll<HTMLInputElement>('input[name=level]')) {
    r.addEventListener('change', () => void save((s) => ({ ...s, strictness: r.value as Strictness })));
  }
  $('firewall').addEventListener('change', (e) => void save((s) => ({ ...s, firewall: (e.target as HTMLInputElement).checked })));
  $('clipboard').addEventListener('change', (e) => void save((s) => ({ ...s, clipboardGuard: (e.target as HTMLInputElement).checked })));
  $('rdap').addEventListener('change', (e) => void save((s) => ({ ...s, rdapLookup: (e.target as HTMLInputElement).checked })));

  $('sync').addEventListener('click', async () => {
    const b = $('sync') as HTMLButtonElement;
    b.disabled = true;
    msg('syncMsg', 'Actualizando…');
    const r = (await chrome.runtime.sendMessage({ type: 'lists:sync' })) as Array<{ source: string; result: string }> | null;
    const errs = (r ?? []).filter((x) => x.result.startsWith('error'));
    msg('syncMsg', errs.length ? `Terminado con ${errs.length} error(es).` : 'Listas actualizadas.', errs.length === 0);
    b.disabled = false;
    await refresh();
  });

  $('addForm').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const input = $('addHost') as HTMLInputElement;
    let raw = input.value.trim();
    try {
      if (/^https?:\/\//i.test(raw)) raw = new URL(raw).hostname;
      else if (/[^\x00-\x7f]/.test(raw)) raw = new URL(`http://${raw}`).hostname;
    } catch {
      /* se valida abajo */
    }
    const h = normalizeHost(raw);
    if (!h) return msg('addMsg', 'Escribe un dominio válido, por ejemplo app.uniswap.org.', false);
    if ((lastState?.settings.allowlist.length ?? 0) >= MAX_ALLOWLIST) return msg('addMsg', 'Llegaste al máximo de sitios.', false);
    void save((s) => ({ ...s, allowlist: s.allowlist.includes(h) ? s.allowlist : [...s.allowlist, h] })).then(() => {
      input.value = '';
      msg('addMsg', `${hostToUnicode(h)} agregado.`);
    });
  });

  $('simSave').addEventListener('click', async () => {
    const account = ($('simAccount') as HTMLInputElement).value.trim();
    const project = ($('simProject') as HTMLInputElement).value.trim();
    const key = ($('simKey') as HTMLInputElement).value.trim();
    const enabled = ($('simEnabled') as HTMLInputElement).checked;
    if (enabled && (!SLUG.test(account) || !SLUG.test(project))) return msg('simMsg', 'Completa cuenta y proyecto (letras, números, guiones).', false);
    if (key) await chrome.runtime.sendMessage({ type: 'secret:set', key });
    const status = (await chrome.runtime.sendMessage({ type: 'secret:status' })) as { hasKey?: boolean } | null;
    if (enabled && !status?.hasKey) return msg('simMsg', 'Falta la API key.', false);
    await save((s) => ({ ...s, simulation: { enabled, account, project } }));
    ($('simKey') as HTMLInputElement).value = '';
    ($('simKey') as HTMLInputElement).placeholder = status?.hasKey ? 'key guardada (escribe para reemplazarla)' : 'sin key';
    msg('simMsg', enabled ? 'Simulación activada.' : 'Guardado (simulación desactivada).');
  });
  $('simClear').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'secret:set', key: '' });
    await save((s) => ({ ...s, simulation: { ...s.simulation, enabled: false } }));
    ($('simKey') as HTMLInputElement).placeholder = 'sin key';
    msg('simMsg', 'API key borrada y simulación desactivada.');
  });

  $('export').addEventListener('click', () => {
    if (!lastState) return;
    const blob = new Blob([exportSettings(lastState.settings)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `walletshield-config-${new Date().toISOString().slice(0, 10)}.json` });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
    msg('ioMsg', 'Configuración exportada.');
  });
  $('import').addEventListener('change', async (ev) => {
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;
    try {
      const imported = importSettings(await file.text());
      // La simulación nunca se activa por importación (requiere una key local).
      await save(() => parseSettings({ ...imported, simulation: { ...imported.simulation, enabled: false } }));
      msg('ioMsg', `Configuración importada (${imported.allowlist.length} sitios de confianza).`);
    } catch (e) {
      msg('ioMsg', e instanceof Error ? e.message : 'No se pudo importar.', false);
    }
    (ev.target as HTMLInputElement).value = '';
  });

  $('filter').addEventListener('change', () => lastState && renderLog(lastState));
  $('clearLog').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'events:clear' });
    await refresh();
  });
}

void main();
