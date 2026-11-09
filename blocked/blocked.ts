import type { BlockedContext } from '../shared/messages';
import { RISK_LABEL, reasonText } from '../shared/texts-es';
import { hostToUnicode } from '../shared/domain/punycode';

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`falta #${id}`);
  return el;
}

async function main(): Promise<void> {
  // Anti-clickjacking: esta página nunca debe funcionar dentro de un iframe.
  if (window.top !== window) return;

  const ctx = (await chrome.runtime.sendMessage({ type: 'blocked:context' })) as BlockedContext | null;
  const app = $('app');
  const host = ctx?.host ?? null;

  $('host').textContent = host ? hostToUnicode(host) : 'Sitio desconocido';
  $('risk').textContent = RISK_LABEL[ctx?.risk ?? 'high'];
  if (ctx?.kind === 'heuristic') {
    $('title').textContent = 'Este sitio parece una imitación';
    $('summary').textContent = 'WalletShield detectó señales de que este dominio imita a un sitio cripto conocido. Las páginas así suelen pedir que conectes tu wallet y firmes algo que vacía tus fondos.';
  } else {
    $('summary').textContent = 'Este dominio está en una lista pública de sitios de phishing cripto. Si lo abriste desde un enlace en redes, un correo o un anuncio, ciérralo.';
  }
  const ul = $('reasons');
  for (const r of ctx?.reasons ?? []) {
    const li = document.createElement('li');
    li.textContent = reasonText(r); // textContent: nunca HTML
    ul.append(li);
  }
  app.hidden = false;

  $('back').addEventListener('click', () => {
    void chrome.tabs.update({ url: 'chrome://newtab/' });
  });

  const ack = $('ack') as HTMLInputElement;
  const proceed = $('proceed') as HTMLButtonElement;
  ack.addEventListener('change', () => {
    proceed.disabled = !ack.checked;
  });
  proceed.addEventListener('click', (ev) => {
    if (!ev.isTrusted || !ack.checked || !host) return;
    proceed.disabled = true;
    void chrome.runtime.sendMessage({ type: 'blocked:proceed', host });
  });
}

void main();
