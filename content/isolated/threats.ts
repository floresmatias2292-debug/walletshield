/** Registro de comportamientos sospechosos observados en la página actual. */
import type { ThreatKind } from '../../shared/bridge';
import type { RiskLevel } from '../../shared/risk';

export interface PageThreat {
  readonly id: string;
  readonly risk: RiskLevel;
  /** Completa la frase "Esta página …". */
  readonly text: string;
}

export const THREAT_TEXT: Record<ThreatKind | 'request-burst', { risk: RiskLevel; text: string }> = {
  'provider-overwrite': { risk: 'high', text: 'reemplazó el provider de tu wallet con un script propio.' },
  'provider-tamper': { risk: 'medium', text: 'modificó funciones del provider de tu wallet.' },
  'wallet-channel': { risk: 'high', text: 'intentó hablar directamente con tu wallet salteando los controles (bloqueado).' },
  'clipboard-write': { risk: 'high', text: 'intentó escribir una dirección en tu portapapeles sin que hicieras nada (bloqueado).' },
  'clipboard-copy-swap': { risk: 'high', text: 'cambió la dirección que copiaste por otra (se restauró la original).' },
  'tx-changed': { risk: 'high', text: 'cambió una transacción después de que la aprobaras (bloqueada).' },
  'request-burst': { risk: 'high', text: 'insiste con solicitudes de firma peligrosas una y otra vez.' },
};

const threats = new Map<string, PageThreat>();

/** Agrega una amenaza; devuelve true si es nueva. */
export function addThreat(t: PageThreat): boolean {
  if (threats.has(t.id)) return false;
  threats.set(t.id, t);
  return true;
}

export function pageThreats(): PageThreat[] {
  return [...threats.values()];
}

// Ráfaga: muchas solicitudes de riesgo alto o bloqueadas en poco tiempo.
const BURST_N = 4;
const BURST_MS = 60_000;
const risky: number[] = [];
export function noteRiskyRequest(now = Date.now()): boolean {
  risky.push(now);
  while (risky.length && now - risky[0]! > BURST_MS) risky.shift();
  return risky.length >= BURST_N;
}
