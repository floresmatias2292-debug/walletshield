/**
 * Aviso no bloqueante (Shadow DOM cerrado). Se usa para amenazas que no
 * requieren decisión: script sospechoso detectado, portapapeles alterado…
 */
import type { RiskLevel } from '../../shared/risk';

const CSS = `
:host { all: initial; }
.t { position: fixed; top: 16px; right: 16px; max-width: min(420px, calc(100vw - 32px)); z-index: 2147483647;
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #1f2328; background: #fff;
  border-left: 5px solid #c62828; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,.3); padding: 12px 36px 12px 14px; }
.t.medium { border-left-color: #b45309; } .t.low { border-left-color: #2563eb; }
@media (prefers-color-scheme: dark) { .t { background: #16181d; color: #e6e8eb; } }
b { display: block; margin-bottom: 2px; }
button { position: absolute; top: 6px; right: 8px; border: 0; background: transparent; font-size: 18px; cursor: pointer; color: inherit; }
`;

export function toast(title: string, text: string, risk: RiskLevel = 'high', ms = 15000): void {
  const host = document.createElement('div');
  host.setAttribute('style', 'all: initial !important; position: fixed !important; z-index: 2147483647 !important; top: 0 !important; right: 0 !important;');
  const root = host.attachShadow({ mode: 'closed' });
  try {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    root.adoptedStyleSheets = [sheet];
  } catch {
    const st = document.createElement('style');
    st.textContent = CSS;
    root.append(st);
  }
  const box = document.createElement('div');
  box.className = `t ${risk}`;
  box.setAttribute('role', 'alert');
  const b = document.createElement('b');
  b.textContent = `🛡 WalletShield · ${title}`;
  const p = document.createElement('div');
  p.textContent = text;
  const x = document.createElement('button');
  x.type = 'button';
  x.textContent = '×';
  x.setAttribute('aria-label', 'Cerrar');
  x.addEventListener('click', () => host.remove());
  box.append(b, p, x);
  root.append(box);
  (document.documentElement ?? document).append(host);
  setTimeout(() => host.remove(), ms);
}
