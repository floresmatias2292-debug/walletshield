/**
 * Mensajes entre contextos de la extensión. Todo mensaje entrante se valida
 * con estas funciones antes de usarse; los que no validan se descartan.
 */
import type { DomainReason } from './domain/typosquat';
import type { RiskLevel } from './risk';

/** Mensajes que solo pueden enviar páginas propias de la extensión. */
export type PrivilegedRequest =
  | { type: 'blocked:context' }
  | { type: 'blocked:proceed'; host: string }
  | { type: 'state:get' };

export interface BlockedContext {
  readonly url: string | null;
  readonly host: string | null;
  readonly kind: 'list' | 'heuristic';
  readonly risk: RiskLevel;
  readonly reasons: readonly DomainReason[];
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const HOST_MAX = 253;

export function parsePrivilegedRequest(msg: unknown): PrivilegedRequest | null {
  if (!isObj(msg) || typeof msg.type !== 'string') return null;
  switch (msg.type) {
    case 'blocked:context':
    case 'state:get':
      return { type: msg.type };
    case 'blocked:proceed':
      if (typeof msg.host !== 'string' || msg.host.length > HOST_MAX) return null;
      return { type: 'blocked:proceed', host: msg.host };
    default:
      return null;
  }
}

/**
 * true si el remitente es una página de esta misma extensión (no un content
 * script ni otra extensión). Los content scripts tienen sender.origin igual
 * al de la página web.
 */
export function isExtensionPageSender(sender: chrome.runtime.MessageSender, extensionId: string): boolean {
  if (sender.id !== extensionId) return false;
  const origin = `chrome-extension://${extensionId}`;
  if (sender.origin !== undefined) return sender.origin === origin;
  return typeof sender.url === 'string' && sender.url.startsWith(`${origin}/`);
}
