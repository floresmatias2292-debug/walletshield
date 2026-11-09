/**
 * Guardia del portapapeles del lado del usuario:
 *  - recuerda la última dirección que copiaste (en cualquier pestaña, vía el
 *    service worker y solo en memoria de sesión);
 *  - al pegar, si la dirección se PARECE a la copiada pero no es igual
 *    (address poisoning / malware "clipper"), bloquea el pegado y avisa.
 */
import { findAddresses, isLookalike, sameAddress, shortAddress } from '../../shared/addresses';
import { toast } from './toast';

let lastCopied: { address: string; t: number } | null = null;
let enabled = true;
const RECENT_MS = 10 * 60_000;
let lastRefresh = 0;

/** Consulta la última dirección copiada (en cualquier pestaña) y si la guardia está activa. */
function refresh(): void {
  const now = Date.now();
  if (now - lastRefresh < 1000) return;
  lastRefresh = now;
  void chrome.runtime
    .sendMessage({ type: 'clip:get' })
    .then((r: unknown) => {
      const o = (r ?? {}) as { enabled?: unknown; lastCopied?: { address?: unknown; t?: unknown } | null };
      enabled = o.enabled !== false;
      const lc = o.lastCopied;
      if (lc && typeof lc.address === 'string' && typeof lc.t === 'number') {
        if (!lastCopied || lc.t > lastCopied.t) lastCopied = { address: lc.address, t: lc.t };
      }
    })
    .catch(() => undefined);
}

function isEditable(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  return t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t.isContentEditable;
}

export function installClipboardGuard(onThreat: (text: string) => void): void {
  addEventListener(
    'copy',
    () => {
      const sel = getSelection()?.toString() ?? '';
      const found = findAddresses(sel);
      if (found.length !== 1) return;
      lastCopied = { address: found[0]!.value, t: Date.now() };
      void chrome.runtime.sendMessage({ type: 'clip:copy', address: found[0]!.value }).catch(() => undefined);
    },
    true,
  );
  // Solo se consulta al service worker cuando el usuario enfoca un campo
  // editable (justo antes de pegar), no en cada carga de página.
  addEventListener(
    'focusin',
    (ev) => {
      if (isEditable(ev.target)) refresh();
    },
    true,
  );

  addEventListener(
    'paste',
    (ev: ClipboardEvent) => {
      if (!ev.isTrusted || !enabled || !lastCopied || Date.now() - lastCopied.t > RECENT_MS) return;
      const text = ev.clipboardData?.getData('text/plain') ?? '';
      const pasted = findAddresses(text);
      if (pasted.length !== 1) return;
      const p = pasted[0]!.value;
      if (sameAddress(p, lastCopied.address)) return;
      if (isLookalike(p, lastCopied.address)) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        toast(
          'Pegado bloqueado',
          `La dirección que ibas a pegar (${shortAddress(p)}) NO es la que copiaste (${shortAddress(lastCopied.address)}), aunque empieza y termina igual. Es un engaño típico (address poisoning o malware en el portapapeles). Vuelve a copiarla desde una fuente confiable.`,
          'high',
          30000,
        );
        onThreat('pegó una dirección parecida a la que copiaste, pero distinta (bloqueado).');
      } else {
        toast(
          'Revisa la dirección',
          `Pegaste ${shortAddress(p)}, pero la última dirección que copiaste en el navegador fue ${shortAddress(lastCopied.address)}. Si no la cambiaste a propósito, verifica antes de enviar.`,
          'medium',
        );
      }
    },
    true,
  );
}
