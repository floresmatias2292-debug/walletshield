/**
 * Clasificación de la contraparte (spender, operator, destinatario) y
 * matriz de riesgo de aprobaciones, compartida por transacciones y firmas.
 */
import type { RiskLevel } from '../risk';
import type { AnalysisContext } from './context';
import { isUnlimited } from './hex';
import { knownContract } from './known';
import { describeAddress } from './format';
import type { Finding } from './types';

export type CounterpartyKind = 'bad' | 'known' | 'eoa' | 'contract' | 'unknown';

export interface Counterparty {
  readonly address: string;
  readonly kind: CounterpartyKind;
  readonly label: string;
}

export function classify(ctx: AnalysisContext, address: string): Counterparty {
  const a = address.toLowerCase();
  const label = describeAddress(ctx, a);
  if (ctx.isBad(a)) return { address: a, kind: 'bad', label };
  if (knownContract(a, ctx.chainId)) return { address: a, kind: 'known', label };
  const c = ctx.isContract(a);
  return { address: a, kind: c === true ? 'contract' : c === false ? 'eoa' : 'unknown', label };
}

export function counterpartyFinding(cp: Counterparty, role: string): Finding | null {
  switch (cp.kind) {
    case 'bad':
      return { code: 'bad-address', risk: 'high', text: `${role} (${cp.label}) figura en listas públicas de drainers.` };
    case 'eoa':
      return {
        code: 'counterparty',
        risk: 'medium',
        text: `${role} (${cp.label}) es una cuenta personal, no un contrato. Los drainers suelen pedir permisos para sus propias cuentas.`,
      };
    case 'contract':
      return { code: 'counterparty', risk: 'low', text: `${role} (${cp.label}) es un contrato que WalletShield no reconoce.` };
    case 'unknown':
      return { code: 'counterparty', risk: 'low', text: `No se pudo verificar qué es ${cp.label}.` };
    case 'known':
      return null;
  }
}

/**
 * Riesgo de autorizar a `cp` a mover `amount` de un token.
 * `shortLived`: el permiso vence pronto (≤ 90 días), como los de Uniswap.
 */
export function approvalRisk(cp: Counterparty, amount: bigint, shortLived = false): RiskLevel {
  if (amount === 0n) return 'none';
  const unlimited = isUnlimited(amount);
  switch (cp.kind) {
    case 'bad':
      return 'high';
    case 'eoa':
      return unlimited ? 'high' : 'medium';
    case 'known':
      return unlimited && !shortLived ? 'medium' : unlimited ? 'low' : 'none';
    case 'contract':
      return unlimited ? 'high' : 'low';
    case 'unknown':
      return unlimited ? 'high' : 'medium';
  }
}
