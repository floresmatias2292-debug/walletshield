import { DomainAnalyzer } from '../shared/domain/typosquat';
import { hostnameFromUrl, hostAndParents } from '../shared/domain/normalize';
import { hostToUnicode } from '../shared/domain/punycode';
import { reasonText } from '../shared/texts-es';
import { $, ago, el, loadState, todayCount, updateSettings, type UiState } from '../ui/store';

const LEVEL: Record<string, string> = {
  relaxed: 'Nivel: relajado (solo riesgo alto)',
  normal: 'Nivel: normal (riesgo medio y alto)',
  strict: 'Nivel: estricto (todo aviso + bloqueos automáticos)',
};

async function currentHost(): Promise<string | null> {
  // ?tab=ID solo se usa en los tests automáticos (el popup real no recibe parámetros).
  const forced = Number(new URLSearchParams(location.search).get('tab'));
  const tab = forced ? await chrome.tabs.get(forced) : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  return tab?.url ? hostnameFromUrl(tab.url) : null;
}

function isTrusted(host: string, list: readonly string[]): string | null {
  for (const p of hostAndParents(host)) if (list.includes(p)) return p;
  return null;
}

async function render(state: UiState, host: string | null): Promise<void> {
  const s = state.settings;
  const status = $('status');
  if (!s.firewall) {
    status.className = 'pill warn';
    status.textContent = 'Firewall desactivado';
  } else {
    status.className = 'pill ok';
    status.textContent = 'Protección activa';
  }
  ($('fw') as HTMLInputElement).checked = s.firewall;
  ($('clip') as HTMLInputElement).checked = s.clipboardGuard;
  $('level').textContent = LEVEL[s.strictness] ?? '';
  $('today').textContent = String(todayCount(state.stats));
  $('total').textContent = String(state.stats?.blockedTotal ?? 0);

  // Sitio actual
  const verdict = $('verdict');
  const trust = $('trust') as HTMLButtonElement;
  if (!host) {
    $('host').textContent = 'Página interna del navegador';
    verdict.textContent = '';
    trust.hidden = true;
  } else {
    $('host').textContent = hostToUnicode(host);
    const trustedBy = isTrusted(host, s.allowlist);
    const v = new DomainAnalyzer().analyze(host);
    if (trustedBy) {
      verdict.className = 'small ok';
      verdict.textContent = `Sitio de confianza${trustedBy !== host ? ` (por ${trustedBy})` : ''}.`;
    } else if (v.legit) {
      verdict.className = 'small ok';
      verdict.textContent = 'Dominio oficial conocido.';
    } else if (v.risk === 'high' || v.risk === 'medium') {
      verdict.className = `small ${v.risk === 'high' ? 'danger' : 'warn'}`;
      verdict.textContent = v.reasons.map(reasonText).join(' ');
    } else {
      verdict.className = 'small';
      verdict.textContent = 'Sin señales de imitación.';
    }
    trust.hidden = false;
    trust.textContent = trustedBy ? 'Quitar de sitios de confianza' : 'Confiar en este sitio';
    trust.className = trustedBy ? 'danger' : '';
    trust.onclick = async () => {
      await updateSettings((cur) => ({
        ...cur,
        allowlist: trustedBy ? cur.allowlist.filter((h) => h !== trustedBy) : [...cur.allowlist, host],
      }));
      await refresh();
    };
  }

  // Lista de confianza
  const ul = $('trusted');
  ul.replaceChildren();
  $('trustedCount').textContent = String(s.allowlist.length);
  if (!s.allowlist.length) ul.append(el('li', { class: 'muted small' }, 'Todavía no agregaste sitios.'));
  for (const h of s.allowlist.slice(0, 6)) {
    const li = el('li');
    const x = el('button', { class: 'x', type: 'button', 'aria-label': `Quitar ${h}`, title: 'Quitar' }, '×');
    x.addEventListener('click', async () => {
      await updateSettings((cur) => ({ ...cur, allowlist: cur.allowlist.filter((a) => a !== h) }));
      await refresh();
    });
    li.append(el('span', { class: 'mono' }, hostToUnicode(h)), x);
    ul.append(li);
  }
  if (s.allowlist.length > 6) ul.append(el('li', { class: 'muted small' }, `y ${s.allowlist.length - 6} más (ver Opciones)`));

  const last = Math.max(0, ...Object.values(state.sources).map((x) => x.lastSync ?? 0));
  const errors = Object.values(state.sources).filter((x) => x.error).length;
  $('lists').textContent = `Listas actualizadas ${ago(last || null)}${errors ? ` · ${errors} con error` : ''}`;
}

let host: string | null = null;
async function refresh(): Promise<void> {
  await render(await loadState(), host);
}

async function main(): Promise<void> {
  host = await currentHost();
  await refresh();
  $('fw').addEventListener('change', async (e) => {
    const on = (e.target as HTMLInputElement).checked;
    await updateSettings((s) => ({ ...s, firewall: on }));
    await refresh();
  });
  $('clip').addEventListener('change', async (e) => {
    const on = (e.target as HTMLInputElement).checked;
    await updateSettings((s) => ({ ...s, clipboardGuard: on }));
  });
  $('options').addEventListener('click', () => void chrome.runtime.openOptionsPage());
}

void main();
