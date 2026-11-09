/**
 * Análisis de transacciones: eth_sendTransaction, eth_signTransaction y
 * cada llamada de wallet_sendCalls (EIP-5792).
 */
import { maxRisk, type RiskLevel } from '../risk';
import { AbiError, splitCalldata, type AbiReader } from './abi';
import type { AnalysisContext } from './context';
import { approvalRisk, classify, counterpartyFinding } from './counterparty';
import { describeAddress, expiryDays, formatAmount, formatEth, formatExpiry } from './format';
import { isUnlimited, normAddr, toBigInt } from './hex';
import { knownContract, PERMIT2 } from './known';
import { DRAINER_SELECTORS, SEL } from './selectors';
import type { Finding } from './types';

export class Report {
  readonly findings: Finding[] = [];
  readonly summary: string[] = [];
  title = '';

  add(f: Finding | null): void {
    if (f && !this.findings.some((x) => x.code === f.code && x.text === f.text)) this.findings.push(f);
  }

  line(s: string): void {
    this.summary.push(s);
  }

  setTitle(t: string): void {
    if (!this.title) this.title = t;
  }

  get risk(): RiskLevel {
    return this.findings.reduce<RiskLevel>((r, f) => maxRisk(r, f.risk), 'none');
  }
}

export interface TxLike {
  readonly from: string | null;
  readonly to: string | null;
  readonly value: bigint;
  readonly data: string | null;
  readonly authorizationList: boolean;
}

export function parseTx(raw: unknown): TxLike | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const t = raw as Record<string, unknown>;
  const value = t.value === undefined || t.value === null ? 0n : toBigInt(t.value);
  if (value === null) return null;
  const data = typeof t.data === 'string' ? t.data : typeof t.input === 'string' ? t.input : null;
  return {
    from: normAddr(t.from),
    to: normAddr(t.to),
    value,
    data,
    authorizationList: Array.isArray(t.authorizationList) && t.authorizationList.length > 0,
  };
}

const MAX_DEPTH = 2;

/** Aprobación de un token ERC-20 (approve / increaseAllowance / permit on-chain). */
function reportApproval(ctx: AnalysisContext, r: Report, token: string, spender: string, amount: bigint, how: string): void {
  const cp = classify(ctx, spender);
  const risk = approvalRisk(cp, amount);
  const amountText = formatAmount(ctx, token, amount);
  if (amount === 0n) {
    r.setTitle('Revocar una aprobación');
    r.line(`Quita el permiso de ${cp.label} sobre ${formatAmount(ctx, token, 0n).replace(/^0 /, '')}.`);
    r.add({ code: 'approval-revoke', risk: 'none', text: 'Es una revocación: reduce tu riesgo.' });
    return;
  }
  r.setTitle(isUnlimited(amount) ? 'Aprobación ILIMITADA de un token' : 'Aprobación de un token');
  r.line(`Autorizas a ${cp.label} a mover ${amountText} de tu wallet (${how}).`);
  if (isUnlimited(amount)) {
    r.add({
      code: 'unlimited-approval',
      risk,
      text:
        cp.kind === 'known'
          ? `Aprobación ilimitada a ${cp.label}, un contrato oficial conocido. Es habitual, pero si ese contrato fuera vulnerado podría vaciar ese token.`
          : `Aprobación ilimitada: ${cp.label} podrá llevarse TODO tu saldo de ese token, ahora y en el futuro, sin volver a pedirte permiso.`,
    });
  } else {
    r.add({ code: 'approval', risk, text: `Permiso limitado a ${amountText}.` });
  }
  r.add(counterpartyFinding(cp, 'El destinatario del permiso'));
}

function reportApprovalForAll(ctx: AnalysisContext, r: Report, collection: string, operator: string, approved: boolean): void {
  const cp = classify(ctx, operator);
  if (!approved) {
    r.setTitle('Revocar acceso a una colección');
    r.line(`Quita a ${cp.label} el permiso sobre ${describeAddress(ctx, collection)}.`);
    r.add({ code: 'approval-revoke', risk: 'none', text: 'Es una revocación: reduce tu riesgo.' });
    return;
  }
  r.setTitle('Acceso TOTAL a una colección (setApprovalForAll)');
  r.line(`Autorizas a ${cp.label} a transferir TODOS tus NFTs/tokens de ${describeAddress(ctx, collection)}.`);
  const risk: RiskLevel = cp.kind === 'known' ? 'medium' : 'high';
  r.add({
    code: 'approval-for-all',
    risk,
    text:
      cp.kind === 'known'
        ? `${cp.label} es un marketplace conocido; aun así, este permiso cubre toda la colección.`
        : `setApprovalForAll da control sobre toda la colección. Es la técnica más usada para robar NFTs.`,
  });
  r.add(counterpartyFinding(cp, 'El operador'));
}

function reportTransfer(ctx: AnalysisContext, r: Report, token: string, from: string | null, to: string, amount: bigint | null, nft: boolean): void {
  const cp = classify(ctx, to);
  if (nft) {
    r.setTitle('Transferencia de NFT');
    r.line(`Envías un NFT de ${describeAddress(ctx, token)} a ${cp.label}.`);
    r.add({ code: 'nft-transfer', risk: cp.kind === 'bad' ? 'high' : 'low', text: 'Una transferencia de NFT no se puede deshacer.' });
  } else if (amount !== null) {
    r.setTitle('Transferencia de tokens');
    r.line(`Envías ${formatAmount(ctx, token, amount)} a ${cp.label}.`);
    const owner = from ?? ctx.account;
    const bal = owner ? ctx.tokenBalance(token, owner) : null;
    if (bal !== null && bal > 0n && amount * 100n >= bal * 95n) {
      r.add({
        code: 'token-transfer',
        risk: cp.kind === 'contract' || cp.kind === 'unknown' ? 'high' : 'medium',
        text: 'Transfieres prácticamente todo tu saldo de este token.',
      });
    }
  }
  if (cp.kind === 'bad') r.add(counterpartyFinding(cp, 'El destinatario'));
}

/** Decodifica una llamada a contrato. Devuelve false si el selector no es de interés. */
function analyzeCall(ctx: AnalysisContext, r: Report, target: string, from: string | null, data: string, depth: number): void {
  const cd = splitCalldata(data);
  if (!cd) return;
  const a: AbiReader = cd.args;
  try {
    switch (cd.selector) {
      case SEL.approve:
        if (target === PERMIT2) break; // Permit2 no tiene approve(address,uint256)
        reportApproval(ctx, r, target, a.address(0), a.uint(1), 'approve');
        return;
      case SEL.increaseAllowance:
      case SEL.increaseApproval:
        reportApproval(ctx, r, target, a.address(0), a.uint(1), 'increaseAllowance');
        return;
      case SEL.permit2612:
        reportApproval(ctx, r, target, a.address(1), a.uint(2), 'permit');
        return;
      case SEL.permitDai:
        reportApproval(ctx, r, target, a.address(1), a.bool(4) ? (1n << 256n) - 1n : 0n, 'permit');
        return;
      case SEL.permit2Approve: {
        if (target !== PERMIT2) break;
        const token = a.address(0);
        const spender = a.address(1);
        const amount = a.uint(2);
        const exp = a.uint(3);
        const cp = classify(ctx, spender);
        const days = expiryDays(ctx, exp);
        r.setTitle('Aprobación vía Permit2');
        r.line(`Autorizas a ${cp.label} a mover ${formatAmount(ctx, token, amount)} vía Permit2 (${formatExpiry(ctx, exp)}).`);
        r.add({ code: 'permit2', risk: approvalRisk(cp, amount, days <= 90), text: 'Aprobación de Permit2 sobre un token.' });
        r.add(counterpartyFinding(cp, 'El destinatario del permiso'));
        return;
      }
      case SEL.permit2Lockdown:
        if (target === PERMIT2) {
          r.setTitle('Revocar permisos de Permit2');
          r.add({ code: 'approval-revoke', risk: 'none', text: 'Revoca permisos de Permit2: reduce tu riesgo.' });
          return;
        }
        break;
      case SEL.setApprovalForAll:
        reportApprovalForAll(ctx, r, target, a.address(0), a.bool(1));
        return;
      case SEL.transfer:
        reportTransfer(ctx, r, target, from, a.address(0), a.uint(1), false);
        return;
      case SEL.transferFrom: {
        const src = a.address(0);
        const dst = a.address(1);
        const amt = a.uint(2);
        // Mismo selector para ERC-20 y ERC-721: si "from" eres tú, es un envío tuyo.
        const mine = from !== null && src === from;
        if (mine) reportTransfer(ctx, r, target, from, dst, amt, false);
        else reportTransfer(ctx, r, target, src, dst, null, false);
        return;
      }
      case SEL.safeTransferFrom721:
      case SEL.safeTransferFrom721Data:
      case SEL.safeTransferFrom1155:
      case SEL.safeBatchTransferFrom1155:
        reportTransfer(ctx, r, target, a.address(0), a.address(1), null, true);
        return;
      case SEL.multicall:
      case SEL.multicallDeadline:
      case SEL.multicallBlockHash: {
        if (depth >= MAX_DEPTH) return;
        const calls = a.bytesArray(cd.selector === SEL.multicall ? 0 : 1);
        for (const c of calls) analyzeCall(ctx, r, target, from, `0x${c}`, depth + 1);
        return;
      }
    }
  } catch (e) {
    if (e instanceof AbiError) {
      r.add({ code: 'undecodable', risk: 'medium', text: 'Los datos de la transacción están malformados y no se pudieron leer.' });
      return;
    }
    throw e;
  }
}

/** Analiza una transacción (o una llamada de un lote). */
export function analyzeTx(ctx: AnalysisContext, r: Report, tx: TxLike, depth = 0): void {
  const from = tx.from ?? ctx.account;
  if (tx.authorizationList) {
    r.setTitle('Delegar tu cuenta a un contrato (EIP-7702)');
    r.add({
      code: 'eip7702',
      risk: 'high',
      text: 'La transacción incluye una autorización EIP-7702: tu cuenta pasaría a ejecutar el código de otro contrato, que podría mover todos tus fondos.',
    });
  }
  if (!tx.to) {
    if (tx.data && tx.data.length > 2) {
      r.setTitle('Desplegar un contrato');
      r.add({ code: 'contract-creation', risk: 'low', text: 'Esta transacción crea un contrato nuevo.' });
    }
    return;
  }
  const to = tx.to;
  const cp = classify(ctx, to);
  if (cp.kind === 'bad') r.add(counterpartyFinding(cp, 'El destino'));

  const selector = tx.data && tx.data.length >= 10 ? tx.data.slice(0, 10).toLowerCase() : null;

  if (tx.value > 0n) {
    r.setTitle(selector ? 'Interacción con contrato enviando ETH' : 'Envío de ETH');
    r.line(`Envías ${formatEth(tx.value, ctx.chainId)} a ${cp.label}.`);
    const drainerFn = selector ? DRAINER_SELECTORS[selector] : undefined;
    if (drainerFn) {
      r.add({
        code: 'drainer-function',
        risk: 'high',
        text: `Llama a la función ${drainerFn} enviando ETH: es el patrón de los falsos "claim" y "security update" de los drainers.`,
      });
    }
    const bal = from ? ctx.nativeBalance(from) : null;
    if (bal !== null && bal > 0n && tx.value * 100n >= bal * 90n) {
      const risk: RiskLevel = cp.kind === 'known' ? 'low' : cp.kind === 'eoa' ? 'medium' : 'high';
      r.add({ code: 'native-drain', risk, text: 'Envías el 90 % o más de tu saldo de ETH en una sola transacción.' });
    } else if (selector && cp.kind === 'contract' && !drainerFn) {
      r.add({ code: 'value-to-contract', risk: 'low', text: `Envías ETH a un contrato que WalletShield no reconoce.` });
    }
  }
  if (tx.data && selector) {
    analyzeCall(ctx, r, to, from, tx.data, depth);
    if (!r.title) r.setTitle(knownContract(to, ctx.chainId) ? `Interacción con ${cp.label}` : 'Interacción con un contrato');
  }
}

export function analyzeBatch(ctx: AnalysisContext, r: Report, calls: unknown[], from: string | null): void {
  r.setTitle(`Lote de ${calls.length} operaciones`);
  let approvals = 0;
  for (const raw of calls.slice(0, 64)) {
    const tx = parseTx({ ...(raw as object), from });
    if (!tx) {
      r.add({ code: 'undecodable', risk: 'medium', text: 'Una de las operaciones del lote no se pudo leer.' });
      continue;
    }
    const before = r.findings.length;
    analyzeTx(ctx, r, tx, 1);
    if (r.findings.slice(before).some((f) => ['approval', 'unlimited-approval', 'approval-for-all', 'permit2'].includes(f.code) && f.risk !== 'none')) approvals++;
  }
  if (calls.length > 1) {
    r.add({
      code: 'batch-calls',
      risk: approvals > 0 ? 'medium' : 'low',
      text: `Se ejecutan ${calls.length} operaciones juntas en una sola firma${approvals ? ', incluyendo permisos sobre tus tokens' : ''}. Revisa cada una.`,
    });
  }
}
