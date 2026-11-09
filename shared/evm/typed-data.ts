/**
 * Firmas EIP-712 (eth_signTypedData_v3/v4): Permit (EIP-2612 y DAI),
 * Permit2 (allowance y signature transfer), órdenes de Seaport y Blur, y un
 * análisis genérico para el resto. Son "gasless": no cuestan gas y por eso
 * los drainers las prefieren; una vez firmadas, el atacante las ejecuta solo.
 */
import { maxRisk, type RiskLevel } from '../risk';
import type { AnalysisContext } from './context';
import { approvalRisk, classify, counterpartyFinding } from './counterparty';
import { describeAddress, expiryDays, formatAmount, formatEth, formatExpiry, shortAddr } from './format';
import { isUnlimited, isZeroAddress, normAddr, toBigInt } from './hex';
import { isWethLike, knownContract, PERMIT2 } from './known';
import type { Report } from './tx';

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Obj) : null;
}

export interface TypedData {
  readonly domain: Obj;
  readonly primaryType: string;
  readonly message: Obj;
}

/** Acepta el JSON como string u objeto; null si no es EIP-712 válido. */
export function parseTypedData(raw: unknown): TypedData | null {
  let v: unknown = raw;
  if (typeof raw === 'string') {
    if (raw.length > 1_000_000) return null;
    try {
      v = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  const o = obj(v);
  if (!o) return null;
  const domain = obj(o.domain) ?? {};
  const message = obj(o.message);
  if (!message || typeof o.primaryType !== 'string') return null;
  return { domain, primaryType: o.primaryType, message };
}

const NOT_SOON_DAYS = 90;
const LONG_EXPIRY_DAYS = 365;

function permit2612(ctx: AnalysisContext, r: Report, td: TypedData): void {
  const token = normAddr(td.domain.verifyingContract);
  const spender = normAddr(td.message.spender);
  if (!token || !spender) {
    r.add({ code: 'undecodable', risk: 'high', text: 'Permiso de token sin contrato o destinatario legible.' });
    return;
  }
  // DAI-style: { holder, spender, nonce, expiry, allowed }
  const isDai = typeof td.message.allowed === 'boolean';
  const amount = isDai ? (td.message.allowed ? (1n << 256n) - 1n : 0n) : (toBigInt(td.message.value) ?? (1n << 256n) - 1n);
  const deadline = toBigInt(isDai ? td.message.expiry : td.message.deadline) ?? 0n;
  const cp = classify(ctx, spender);
  const days = expiryDays(ctx, deadline);
  r.setTitle('Firma de permiso sobre un token (Permit)');
  r.line(`Autorizas a ${cp.label} a mover ${formatAmount(ctx, token, amount)} (el permiso ${formatExpiry(ctx, deadline)}).`);
  r.line('Es una firma sin costo de gas: el permiso se puede usar en cuanto firmes, sin otra confirmación.');
  let risk = approvalRisk(cp, amount, days <= NOT_SOON_DAYS);
  if (risk === 'none' && amount > 0n) risk = 'low';
  r.add({
    code: 'permit',
    risk,
    text: isUnlimited(amount)
      ? `Permiso ILIMITADO por firma: ${cp.label} podría vaciar este token sin pedirte nada más.`
      : 'Permiso de gasto por firma (EIP-2612).',
  });
  if (days > LONG_EXPIRY_DAYS && cp.kind !== 'known') {
    r.add({ code: 'long-expiry', risk: 'medium', text: 'El permiso no vence en más de un año (o nunca).' });
  }
  r.add(counterpartyFinding(cp, 'El destinatario del permiso'));
}

function permit2(ctx: AnalysisContext, r: Report, td: TypedData): void {
  const vc = normAddr(td.domain.verifyingContract);
  if (vc !== PERMIT2) {
    r.add({
      code: 'fake-contract',
      risk: 'high',
      text: `La firma dice ser de "Permit2" pero el contrato ${vc ? shortAddr(vc) : 'indicado'} no es el Permit2 oficial.`,
    });
  }
  const m = td.message;
  const spender = normAddr(m.spender);
  if (!spender) {
    r.add({ code: 'undecodable', risk: 'high', text: 'Firma de Permit2 sin destinatario legible.' });
    return;
  }
  const cp = classify(ctx, spender);
  const transfer = td.primaryType.includes('TransferFrom');
  const items: Array<{ token: string | null; amount: bigint; expiration: bigint | null }> = [];
  if (transfer) {
    const permitted = Array.isArray(m.permitted) ? m.permitted : [m.permitted];
    for (const p of permitted) {
      const po = obj(p);
      items.push({ token: normAddr(po?.token), amount: toBigInt(po?.amount) ?? 0n, expiration: null });
    }
  } else {
    const details = Array.isArray(m.details) ? m.details : [m.details];
    for (const d of details) {
      const dobj = obj(d);
      items.push({ token: normAddr(dobj?.token), amount: toBigInt(dobj?.amount) ?? 0n, expiration: toBigInt(dobj?.expiration) });
    }
  }
  const batch = items.length > 1;
  r.setTitle(transfer ? 'Firma que permite retirar tokens (Permit2)' : batch ? `Permiso sobre ${items.length} tokens (Permit2)` : 'Permiso de token vía Permit2');

  let risk: RiskLevel = 'none';
  for (const it of items) {
    if (!it.token) continue;
    const exp = it.expiration ?? toBigInt(m.deadline) ?? 0n;
    const days = expiryDays(ctx, exp);
    const verb = transfer ? 'retirar' : 'mover';
    r.line(`${cp.label} podrá ${verb} ${formatAmount(ctx, it.token, it.amount)}${it.expiration !== null ? ` (${formatExpiry(ctx, exp)})` : ''}.`);
    let itRisk = approvalRisk(cp, it.amount, days <= NOT_SOON_DAYS);
    if (transfer && cp.kind !== 'known' && it.amount > 0n) itRisk = 'high';
    if (itRisk === 'none' && it.amount > 0n && cp.kind !== 'known') itRisk = 'low';
    risk = maxRisk(risk, itRisk);
  }
  if (batch && cp.kind !== 'known') risk = 'high';
  r.add({
    code: batch ? 'permit-batch' : transfer ? 'permit-transfer' : 'permit2',
    risk,
    text: transfer
      ? cp.kind === 'known'
        ? `Orden firmada para ${cp.label} (por ejemplo, un swap de UniswapX).`
        : 'Esta firma permite a otro retirar tus tokens en cuanto la tenga. Es el método principal de los drainers con Permit2.'
      : batch
        ? `Una sola firma da permiso sobre ${items.length} tokens distintos: patrón típico de drainers (p. ej. Inferno Drainer).`
        : cp.kind === 'known'
          ? `Permiso para ${cp.label}, un contrato oficial.`
          : 'Permiso de Permit2 a un destinatario que WalletShield no reconoce.',
  });
  r.add(counterpartyFinding(cp, 'El destinatario'));
}

interface OfferItem {
  itemType: number;
  token: string | null;
  amount: bigint;
  recipient: string | null;
}

function items(v: unknown): OfferItem[] {
  if (!Array.isArray(v)) return [];
  return v.slice(0, 200).map((x) => {
    const o = obj(x) ?? {};
    return {
      itemType: Number(toBigInt(o.itemType) ?? -1n),
      token: normAddr(o.token),
      amount: toBigInt(o.endAmount) ?? toBigInt(o.startAmount) ?? 0n,
      recipient: normAddr(o.recipient),
    };
  });
}

const ITEM_NAMES: Record<number, string> = { 0: 'ETH', 1: 'token ERC-20', 2: 'NFT', 3: 'NFT (ERC-1155)', 4: 'NFT (cualquiera de la colección)', 5: 'NFT 1155 (cualquiera de la colección)' };
/** Menos de 0,001 ETH se considera "regalado". */
const TINY_WEI = 10n ** 15n;

function seaportOrder(ctx: AnalysisContext, r: Report, m: Obj): RiskLevel {
  const offerer = normAddr(m.offerer) ?? ctx.account;
  const offer = items(m.offer);
  const consideration = items(m.consideration);
  for (const it of offer) {
    const what = it.itemType >= 2 ? `${ITEM_NAMES[it.itemType]} de ${it.token ? describeAddress(ctx, it.token) : '?'}` : it.token && it.itemType === 1 ? formatAmount(ctx, it.token, it.amount) : formatEth(it.amount, ctx.chainId);
    r.line(`Entregas: ${what}.`);
  }
  let paidToYouWei = 0n;
  let otherToYou = false;
  for (const c of consideration) {
    const toYou = c.recipient !== null && offerer !== null && c.recipient === offerer;
    if (!toYou) continue;
    if (c.itemType === 0 || (c.itemType === 1 && c.token && isWethLike(c.token, ctx.chainId))) paidToYouWei += c.amount;
    else otherToYou = true;
  }
  const offersAssets = offer.some((o) => o.itemType >= 1);
  if (paidToYouWei > 0n) r.line(`Recibes: ${formatEth(paidToYouWei, ctx.chainId)}.`);
  if (offersAssets && paidToYouWei < TINY_WEI && !otherToYou) {
    r.add({
      code: 'nft-sale-zero',
      risk: 'high',
      text: 'Pones a la venta tus activos por 0 (o casi 0). Así funcionan los drainers de NFTs: firmas una "orden" y compran todo gratis.',
    });
    return 'high';
  }
  const others = new Set(consideration.filter((c) => c.recipient && c.recipient !== offerer).map((c) => c.recipient as string));
  const end = toBigInt(m.endTime);
  r.add({
    code: 'nft-listing',
    risk: 'low',
    text: `Orden de venta en Seaport${others.size ? ` (comisiones a ${others.size} dirección(es))` : ''}${end ? `, ${formatExpiry(ctx, end)}` : ''}.`,
  });
  return 'low';
}

function flattenBulk(tree: unknown, out: Obj[], depth = 0): void {
  if (depth > 24 || out.length > 512) return;
  if (Array.isArray(tree)) for (const t of tree) flattenBulk(t, out, depth + 1);
  else {
    const o = obj(tree);
    if (o && Array.isArray(o.offer)) out.push(o);
  }
}

function seaport(ctx: AnalysisContext, r: Report, td: TypedData): void {
  const vc = normAddr(td.domain.verifyingContract);
  const k = vc ? knownContract(vc, ctx.chainId) : null;
  if (!k || !k.label.startsWith('Seaport')) {
    r.add({ code: 'fake-contract', risk: 'high', text: 'La firma dice ser de Seaport (OpenSea) pero el contrato no es uno oficial.' });
  }
  if (td.primaryType === 'BulkOrder') {
    const orders: Obj[] = [];
    flattenBulk(td.message.tree, orders);
    r.setTitle(`Firma de ${orders.length} órdenes de venta a la vez (Seaport)`);
    r.add({ code: 'bulk-orders', risk: orders.length > 1 ? 'medium' : 'low', text: `Una sola firma crea ${orders.length} órdenes. Revisa todas.` });
    for (const o of orders.slice(0, 50)) seaportOrder(ctx, r, o);
    return;
  }
  r.setTitle('Orden de venta en Seaport (OpenSea)');
  seaportOrder(ctx, r, td.message);
}

function blur(ctx: AnalysisContext, r: Report, td: TypedData): void {
  if (td.primaryType === 'Root') {
    r.setTitle('Firma ciega de órdenes de Blur');
    r.add({
      code: 'blur-bulk',
      risk: 'high',
      text: 'Firmas un "root" (hash) que agrupa órdenes que no se pueden ver. Los drainers de Blur usan este formato para listar tus NFTs gratis.',
    });
    return;
  }
  const m = td.message;
  const side = Number(toBigInt(m.side) ?? -1n);
  const price = toBigInt(m.price) ?? 0n;
  const collection = normAddr(m.collection);
  r.setTitle(side === 1 ? 'Orden de venta en Blur' : 'Oferta de compra en Blur');
  if (collection) r.line(`Colección: ${describeAddress(ctx, collection)}, token #${String(toBigInt(m.tokenId) ?? '?')}.`);
  r.line(`Precio: ${formatEth(price, ctx.chainId)}.`);
  if (side === 1 && price < TINY_WEI) {
    r.add({ code: 'nft-sale-zero', risk: 'high', text: 'Vendes tu NFT por 0 (o casi 0).' });
  } else {
    r.add({ code: 'nft-listing', risk: 'low', text: 'Orden de Blur con precio visible.' });
  }
}

const SPENDER_KEYS = ['spender', 'operator', 'delegate', 'approved', 'to', 'recipient', 'receiver'];
const AMOUNT_KEYS = ['value', 'amount', 'allowance', 'wad'];

function generic(ctx: AnalysisContext, r: Report, td: TypedData): void {
  const name = typeof td.domain.name === 'string' ? td.domain.name.slice(0, 60) : 'una aplicación';
  r.setTitle(`Firma de datos de ${name}`);
  r.line(`Tipo: ${td.primaryType.slice(0, 60)}.`);
  let flagged = false;
  const walk = (o: Obj, depth: number): void => {
    if (depth > 4 || flagged) return;
    const spenderKey = SPENDER_KEYS.find((k) => normAddr(o[k]));
    const amountKey = AMOUNT_KEYS.find((k) => toBigInt(o[k]) !== null);
    if (spenderKey && amountKey) {
      const spender = normAddr(o[spenderKey]) as string;
      const amount = toBigInt(o[amountKey]) as bigint;
      if (isUnlimited(amount)) {
        const cp = classify(ctx, spender);
        r.line(`Incluye un monto ilimitado a favor de ${cp.label}.`);
        r.add({ code: 'typed-data', risk: cp.kind === 'known' ? 'medium' : 'high', text: 'La firma contiene un monto ilimitado a favor de otra dirección.' });
        flagged = true;
        return;
      }
    }
    for (const v of Object.values(o)) {
      const c = obj(v);
      if (c) walk(c, depth + 1);
    }
  };
  walk(td.message, 0);
  if (!flagged) r.add({ code: 'typed-data', risk: 'low', text: `Firma estructurada (EIP-712) de "${name}". No se detectaron permisos sobre tus fondos.` });
}

export function analyzeTypedData(ctx: AnalysisContext, r: Report, td: TypedData): void {
  const domainChain = toBigInt(td.domain.chainId);
  if (domainChain !== null && ctx.chainId !== null && domainChain !== BigInt(ctx.chainId)) {
    r.add({ code: 'chain-mismatch', risk: 'medium', text: `La firma es para otra red (chainId ${domainChain}) distinta de la conectada (${ctx.chainId}).` });
  }
  const vc = normAddr(td.domain.verifyingContract);
  if (vc && !isZeroAddress(vc) && ctx.isBad(vc)) {
    r.add({ code: 'bad-address', risk: 'high', text: `El contrato ${shortAddr(vc)} figura en listas públicas de drainers.` });
  }
  const name = typeof td.domain.name === 'string' ? td.domain.name : '';
  if (name === 'Permit2' || (td.primaryType.startsWith('Permit') && (td.message.details !== undefined || td.message.permitted !== undefined))) {
    permit2(ctx, r, td);
  } else if (td.primaryType === 'Permit' && td.message.spender !== undefined) {
    permit2612(ctx, r, td);
  } else if (name === 'Seaport' || td.primaryType === 'OrderComponents' || td.primaryType === 'BulkOrder') {
    seaport(ctx, r, td);
  } else if (name === 'Blur Exchange') {
    blur(ctx, r, td);
  } else {
    generic(ctx, r, td);
  }
}
