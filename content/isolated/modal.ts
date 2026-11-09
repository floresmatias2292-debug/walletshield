/**
 * Modal propio de WalletShield.
 *
 * - Shadow DOM cerrado: la página no puede leer ni modificar su contenido.
 * - <dialog> con showModal(): vive en la "top layer", por encima de cualquier
 *   z-index de la página.
 * - Solo se aceptan clics reales (isTrusted) y, con mouse, solo si el punto
 *   clickeado es realmente el modal (anti-clickjacking).
 * - Si la página elimina el modal, la decisión es "Bloquear".
 * - La opción por defecto (foco, Enter, Escape) es siempre "Bloquear".
 */
import type { Analysis } from '../../shared/evm/types';
import type { RiskLevel } from '../../shared/risk';

const RISK_TEXT: Record<RiskLevel, string> = { none: 'Sin riesgo', low: 'Riesgo bajo', medium: 'Riesgo medio', high: 'Riesgo alto' };

const CSS = `
:host { all: initial; }
dialog { all: revert; box-sizing: border-box; width: min(560px, calc(100vw - 32px)); max-height: calc(100vh - 32px); overflow: auto;
  padding: 0; border: 0; border-radius: 14px; background: #fff; color: #1f2328; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  box-shadow: 0 20px 60px rgba(0,0,0,.35); }
dialog::backdrop { background: rgba(10, 12, 16, .62); }
@media (prefers-color-scheme: dark) { dialog { background: #16181d; color: #e6e8eb; } .muted { color: #9aa3ad !important; } .box { background:#1f232a !important; border-color:#2d333b !important; } }
header { display:flex; align-items:center; gap:10px; padding: 16px 20px 0; }
.brand { font-weight: 700; font-size: 13px; letter-spacing: .02em; opacity: .75; }
.badge { margin-left:auto; border-radius: 999px; padding: 2px 10px; font-size: 13px; font-weight: 700; color: #fff; }
.badge.high { background: #c62828; } .badge.medium { background: #b45309; } .badge.low { background: #2563eb; } .badge.none { background: #15803d; }
main { padding: 8px 20px 4px; }
h2 { margin: 6px 0 2px; font-size: 20px; line-height: 1.3; }
.muted { color: #59636e; font-size: 13px; word-break: break-all; }
.box { background: #f6f8fa; border: 1px solid #e3e6ea; border-radius: 10px; padding: 10px 12px; margin: 12px 0; }
.box h3 { margin: 0 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; opacity: .8; }
ul { margin: 0; padding-left: 18px; } li { margin: 4px 0; }
li.high::marker { color: #c62828; } li.medium::marker { color: #b45309; }
details { margin: 8px 0; font-size: 13px; } pre { white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow: auto; font-size: 12px; }
footer { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px 20px 18px; }
label { font-size: 13px; display:flex; gap:6px; align-items:center; width: 100%; }
button { font: inherit; border-radius: 10px; padding: 10px 16px; cursor: pointer; border: 1px solid #d0d7de; background: transparent; color: inherit; }
button.block { background: #c62828; border-color: #c62828; color: #fff; font-weight: 700; flex: 1 1 auto; }
button.go { flex: 0 1 auto; }
button:disabled { opacity: .45; cursor: not-allowed; }
button:focus-visible { outline: 3px solid #60a5fa; outline-offset: 2px; }
`;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text; // nunca innerHTML
  return e;
}

export interface ModalOptions {
  readonly analysis: Analysis;
  readonly host: string;
  readonly hardBlock: boolean;
  readonly technical: string;
}

let queue: Promise<unknown> = Promise.resolve();

/** Muestra el modal y resuelve true solo si el usuario elige "Continuar". */
export function askUser(opts: ModalOptions): Promise<boolean> {
  const run = () => showModal(opts);
  const next = queue.then(run, run);
  queue = next.catch(() => undefined);
  return next;
}

function showModal({ analysis, host, hardBlock, technical }: ModalOptions): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const container = el('div');
    container.setAttribute(
      'style',
      'all: initial !important; position: fixed !important; inset: 0 !important; z-index: 2147483647 !important; display: block !important; pointer-events: none !important;',
    );
    const shadow = container.attachShadow({ mode: 'closed' });
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(CSS);
      shadow.adoptedStyleSheets = [sheet];
    } catch {
      shadow.append(el('style', {}, CSS));
    }

    const dialog = el('dialog', { 'aria-labelledby': 'ws-title' });
    const risk = analysis.risk;

    const header = el('header');
    header.append(el('span', { class: 'brand' }, '🛡 WalletShield'), el('span', { class: `badge ${risk}` }, RISK_TEXT[risk]));

    const main = el('main');
    main.append(el('h2', { id: 'ws-title' }, analysis.title), el('div', { class: 'muted' }, `Sitio: ${host}`));
    if (analysis.summary.length) {
      const box = el('div', { class: 'box' });
      box.append(el('h3', {}, 'Qué estás autorizando'));
      const ul = el('ul');
      for (const s of analysis.summary) ul.append(el('li', {}, s));
      box.append(ul);
      main.append(box);
    }
    const reasons = analysis.findings.filter((f) => f.risk !== 'none');
    if (reasons.length) {
      const box = el('div', { class: 'box' });
      box.append(el('h3', {}, 'Por qué'));
      const ul = el('ul');
      for (const f of reasons) ul.append(el('li', { class: f.risk }, f.text));
      box.append(ul);
      main.append(box);
    }
    const det = el('details');
    det.append(el('summary', {}, 'Detalles técnicos'), el('pre', {}, technical));
    main.append(det);

    const footer = el('footer');
    const blockBtn = el('button', { class: 'block', type: 'button' }, hardBlock ? 'Cerrar' : 'Bloquear');
    footer.append(blockBtn);
    let goBtn: HTMLButtonElement | null = null;
    let ack: HTMLInputElement | null = null;
    if (hardBlock) {
      main.append(el('p', { class: 'muted' }, 'Bloqueado automáticamente por el modo estricto. Puedes cambiarlo en las opciones de WalletShield.'));
    } else {
      goBtn = el('button', { class: 'go', type: 'button' }, 'Continuar de todos modos');
      if (risk === 'high') {
        const label = el('label');
        ack = el('input', { type: 'checkbox' });
        label.append(ack, document.createTextNode('Entiendo que puedo perder mis fondos.'));
        footer.prepend(label);
        goBtn.disabled = true;
      }
      footer.append(goBtn);
    }
    dialog.append(header, main, footer);
    shadow.append(dialog);

    let done = false;
    const finish = (allow: boolean) => {
      if (done) return;
      done = true;
      observer.disconnect();
      try {
        dialog.close();
      } catch {
        /* ya cerrado */
      }
      container.remove();
      resolve(allow);
    };

    // Clic real y sobre el propio modal (no a través de una capa de la página).
    const genuine = (ev: MouseEvent): boolean => {
      if (!ev.isTrusted) return false;
      if (ev.detail === 0) return true; // activado con teclado
      return document.elementFromPoint(ev.clientX, ev.clientY) === container;
    };

    blockBtn.addEventListener('click', () => finish(false)); // bloquear nunca necesita verificación
    dialog.addEventListener('cancel', (ev) => {
      ev.preventDefault();
      finish(false);
    });

    if (goBtn) {
      const btn = goBtn;
      const minDelay = risk === 'high' ? 1500 : 600; // evita clics accidentales o "doble clic" inducido
      const openedAt = performance.now();
      if (ack) {
        const box = ack;
        box.addEventListener('change', () => {
          btn.disabled = !box.checked;
        });
      }
      btn.addEventListener('click', (ev) => {
        if (!genuine(ev)) return;
        if (performance.now() - openedAt < minDelay) return;
        if (ack && !ack.checked) return;
        finish(true);
      });
    }

    // Si la página elimina el modal, se bloquea.
    const observer = new MutationObserver(() => {
      if (!container.isConnected) finish(false);
    });

    (document.documentElement ?? document).append(container);
    observer.observe(document.documentElement, { childList: true });
    container.style.setProperty('pointer-events', 'auto', 'important');
    try {
      dialog.showModal();
    } catch {
      dialog.setAttribute('open', '');
    }
    blockBtn.focus();
  });
}
