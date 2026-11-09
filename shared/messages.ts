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
  | { type: 'state:get' }
  | { type: 'lists:sync' }
  | { type: 'events:clear' }
  | { type: 'secret:set'; key: string }
  | { type: 'secret:status' };

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
    case 'lists:sync':
    case 'events:clear':
    case 'secret:status':
      return { type: msg.type };
    case 'secret:set':
      if (typeof msg.key !== 'string' || msg.key.length > 200 || !/^[\x21-\x7e]*$/.test(msg.key)) return null;
      return { type: 'secret:set', key: msg.key };
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

/** Único mensaje que aceptan los content scripts: reportar una decisión del firewall. */
export interface FirewallEvent {
  readonly type: 'fw:event';
  readonly kind: 'fw-block' | 'fw-allow' | 'fw-auto-block' | 'fw-threat';
  readonly method: string;
  readonly risk: RiskLevel;
  readonly host: string;
  readonly codes: readonly string[];
}

const FW_KINDS = new Set(['fw-block', 'fw-allow', 'fw-auto-block', 'fw-threat']);
const RISKS = new Set(['none', 'low', 'medium', 'high']);

export function parseFirewallEvent(msg: unknown): FirewallEvent | null {
  if (!isObj(msg) || msg.type !== 'fw:event') return null;
  if (typeof msg.kind !== 'string' || !FW_KINDS.has(msg.kind)) return null;
  if (typeof msg.method !== 'string' || msg.method.length > 64) return null;
  if (typeof msg.risk !== 'string' || !RISKS.has(msg.risk)) return null;
  if (typeof msg.host !== 'string' || msg.host.length > HOST_MAX) return null;
  if (!Array.isArray(msg.codes) || msg.codes.length > 8 || !msg.codes.every((c) => typeof c === 'string' && c.length <= 32)) return null;
  return {
    type: 'fw:event',
    kind: msg.kind as FirewallEvent['kind'],
    method: msg.method,
    risk: msg.risk as RiskLevel,
    host: msg.host,
    codes: msg.codes as string[],
  };
}

/** Portapapeles: la última dirección copiada (solo en memoria de sesión del service worker). */
export type ClipMessage = { readonly type: 'clip:copy'; readonly address: string } | { readonly type: 'clip:get' };

export function parseClipMessage(msg: unknown): ClipMessage | null {
  if (!isObj(msg)) return null;
  if (msg.type === 'clip:get') return { type: 'clip:get' };
  if (msg.type === 'clip:copy' && typeof msg.address === 'string' && /^[0-9A-Za-z]{25,64}$/.test(msg.address)) {
    return { type: 'clip:copy', address: msg.address };
  }
  return null;
}

/** Pedidos de content scripts (no confiables) al service worker. */
export type ContentRequest =
  | { readonly type: 'cs:config' }
  | { readonly type: 'sim:run'; readonly chainId: number; readonly blockNumber: number | null; readonly tx: SimTx };

export interface SimTx {
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly data: string;
}

const ADDR = /^0x[0-9a-fA-F]{40}$/;

export function parseContentRequest(msg: unknown): ContentRequest | null {
  if (!isObj(msg)) return null;
  if (msg.type === 'cs:config') return { type: 'cs:config' };
  if (msg.type === 'sim:run' && typeof msg.chainId === 'number' && Number.isSafeInteger(msg.chainId) && isObj(msg.tx)) {
    const t = msg.tx;
    if (typeof t.from !== 'string' || !ADDR.test(t.from) || typeof t.to !== 'string' || !ADDR.test(t.to)) return null;
    if (typeof t.value !== 'string' || !/^(0x[0-9a-fA-F]{0,64}|\d{1,78})$/.test(t.value)) return null;
    if (typeof t.data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(t.data) || t.data.length > 200_000) return null;
    const blockNumber = typeof msg.blockNumber === 'number' && Number.isSafeInteger(msg.blockNumber) && msg.blockNumber > 0 ? msg.blockNumber : null;
    return { type: 'sim:run', chainId: msg.chainId, blockNumber, tx: { from: t.from, to: t.to, value: t.value, data: t.data } };
  }
  return null;
}
