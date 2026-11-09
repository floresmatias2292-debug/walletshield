/**
 * Análisis local de solicitudes a wallets de Solana (Phantom y Wallet
 * Standard): signTransaction, signAllTransactions, signAndSendTransaction,
 * signMessage y signIn.
 */
import { maxRisk, riskAtLeast, type RiskLevel } from '../risk';
import type { Analysis, Finding } from '../evm/types';
import { base64ToBytes, decodeBase58, encodeBase58 } from './base58';
import { parseAny, parseMessage, SolParseError, u32le, u64le, type SolMessage } from './parser';
import { BENIGN_PROGRAMS, LOADER_UPGRADEABLE, PROGRAM_LABELS, STAKE, SYSTEM, TOKEN, TOKEN_2022, U64_MAX } from './programs';
import { bytesToText } from '../evm/hex';

export const SOLANA_METHODS: ReadonlySet<string> = new Set([
  'solana:signTransaction',
  'solana:signAllTransactions',
  'solana:signAndSendTransaction',
  'solana:signAndSendAllTransactions',
  'solana:signMessage',
  'solana:signIn',
]);

export interface SolEncoded {
  readonly b64?: string;
  readonly b58?: string;
  readonly wire: boolean;
}

export interface SolPayload {
  readonly txs?: readonly SolEncoded[];
  readonly message?: SolEncoded;
  readonly signIn?: { readonly domain?: string };
}

export interface SolInput {
  readonly pageHost: string;
  readonly siteRisk: RiskLevel;
  readonly pageThreats?: readonly { readonly risk: RiskLevel; readonly text: string }[];
}

class R {
  findings: Finding[] = [];
  summary: string[] = [];
  title = '';
  add(code: Finding['code'], risk: RiskLevel, text: string): void {
    if (!this.findings.some((f) => f.code === code && f.text === text)) this.findings.push({ code, risk, text });
  }
  get risk(): RiskLevel {
    return this.findings.reduce<RiskLevel>((r, f) => maxRisk(r, f.risk), 'none');
  }
}

const short = (k: string): string => (k.startsWith('tabla:') ? k : `${k.slice(0, 4)}…${k.slice(-4)}`);
const label = (k: string): string => (PROGRAM_LABELS[k] ? `${PROGRAM_LABELS[k]} (${short(k)})` : short(k));

function sol(lamports: bigint): string {
  const whole = lamports / 1_000_000_000n;
  const frac = (lamports % 1_000_000_000n).toString().padStart(9, '0').replace(/0+$/, '');
  return `${whole.toLocaleString('es-AR')}${frac ? `,${frac.slice(0, 6)}` : ''} SOL`;
}

function tokenAmount(v: bigint, decimals: number | null): string {
  if (v >= U64_MAX / 2n) return 'ILIMITADO';
  if (decimals === null) return `${v.toString()} unidades mínimas`;
  const base = 10n ** BigInt(decimals);
  const frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${(v / base).toLocaleString('es-AR')}${frac ? `,${frac.slice(0, 6)}` : ''}`;
}

function decode(e: SolEncoded | undefined): Uint8Array | null {
  if (!e) return null;
  if (typeof e.b64 === 'string') return base64ToBytes(e.b64);
  if (typeof e.b58 === 'string') return decodeBase58(e.b58);
  return null;
}

/** Analiza un mensaje ya parseado y agrega hallazgos. */
export function analyzeSolMessage(r: R, m: SolMessage): void {
  const signers = new Set(m.signers);
  const unknown = new Set<string>();
  let tokenTransfers = 0;
  const solOut = new Map<string, bigint>();
  const recipients = new Set<string>();

  for (const ix of m.instructions) {
    const d = ix.data;
    const acc = ix.accounts;
    if (ix.programId === SYSTEM) {
      if (d.length < 4) continue;
      const kind = u32le(d, 0);
      if (kind === 1 || kind === 10) {
        const target = acc[0] ?? '?';
        const newOwner = d.length >= 36 ? encodeBase58(d.subarray(kind === 1 ? 4 : d.length - 32, kind === 1 ? 36 : d.length)) : '?';
        if (signers.has(target)) {
          r.add('sol-assign', 'high', `Cambia el programa dueño de tu cuenta ${short(target)} a ${label(newOwner)}. Perderías el control de la wallet: es la técnica de "owner change" de los drainers de Solana.`);
        } else {
          r.add('sol-assign', 'low', `Asigna la cuenta ${short(target)} a ${label(newOwner)}.`);
        }
      } else if (kind === 2 || kind === 11) {
        const lamports = u64le(d, 4);
        const from = kind === 2 ? acc[0] : acc[0];
        const to = kind === 2 ? acc[1] : acc[2];
        if (from && to && signers.has(from) && lamports > 0n) {
          solOut.set(to, (solOut.get(to) ?? 0n) + lamports);
          recipients.add(to);
        }
      } else if (kind === 7) {
        r.add('sol-nonce-authority', 'high', 'Cambia la autoridad de una cuenta "durable nonce": quien la controle podría ejecutar una transacción firmada por ti mucho tiempo después.');
      }
    } else if (ix.programId === TOKEN || ix.programId === TOKEN_2022) {
      if (d.length < 1) continue;
      const op = d[0]!;
      if (op === 3 || op === 12) {
        const amount = u64le(d, 1);
        const decimals = op === 12 && d.length >= 10 ? d[9]! : null;
        const owner = op === 3 ? acc[2] : acc[3];
        const dest = op === 3 ? acc[1] : acc[2];
        if (owner && signers.has(owner)) {
          tokenTransfers++;
          if (dest) recipients.add(dest);
          r.summary.push(`Envías ${tokenAmount(amount, decimals)} de un token${op === 12 && acc[1] ? ` (${short(acc[1])})` : ''} a la cuenta ${dest ? short(dest) : '?'}.`);
        }
      } else if (op === 4 || op === 13) {
        const amount = u64le(d, 1);
        const decimals = op === 13 && d.length >= 10 ? d[9]! : null;
        const delegate = op === 4 ? acc[1] : acc[2];
        const unlimited = amount >= U64_MAX / 2n;
        r.summary.push(`Autorizas a ${delegate ? short(delegate) : '?'} a mover ${tokenAmount(amount, decimals)} de tu cuenta de tokens.`);
        r.add(
          unlimited ? 'sol-unlimited-approve' : 'sol-approve',
          unlimited ? 'high' : 'medium',
          unlimited
            ? 'Delegación ILIMITADA: esa dirección podrá llevarse todos esos tokens sin pedirte nada más.'
            : 'Delegas permiso para mover tokens en tu nombre.',
        );
      } else if (op === 6) {
        const type = d[1];
        const target = acc[0] ?? '?';
        const newAuth = d[2] === 1 && d.length >= 35 ? encodeBase58(d.subarray(3, 35)) : null;
        if (type === 2) {
          r.add('sol-owner-change', 'high', `Cambia el DUEÑO de tu cuenta de tokens ${short(target)}${newAuth ? ` a ${short(newAuth)}` : ''}. El nuevo dueño podrá llevarse todo su saldo.`);
        } else if (type === 3) {
          r.add('sol-owner-change', 'high', `Cede a ${newAuth ? short(newAuth) : 'otra cuenta'} la autoridad para cerrar tu cuenta de tokens ${short(target)}.`);
        } else {
          r.add('sol-mint-authority', 'medium', `Cambia una autoridad (tipo ${String(type)}) de ${short(target)}${newAuth ? ` a ${short(newAuth)}` : ''}.`);
        }
      } else if (op === 9) {
        const dest = acc[1];
        if (dest && !signers.has(dest)) {
          r.add('sol-close-account', 'medium', `Cierra una cuenta de tokens y envía su depósito a ${short(dest)}, que no eres tú.`);
        }
      }
    } else if (ix.programId === STAKE) {
      if (d.length >= 4 && [1, 8, 10, 11].includes(u32le(d, 0))) {
        r.add('sol-stake-authority', 'high', 'Cambia la autoridad de una cuenta de staking: quien la reciba podrá retirar ese SOL.');
      }
    } else if (ix.programId === LOADER_UPGRADEABLE) {
      if (d.length >= 4 && [4, 7].includes(u32le(d, 0))) {
        r.add('sol-upgrade-authority', 'high', 'Cambia la autoridad de actualización de un programa.');
      }
    } else if (!BENIGN_PROGRAMS.has(ix.programId) && !PROGRAM_LABELS[ix.programId]) {
      unknown.add(ix.programId);
    }
  }

  for (const [to, lamports] of solOut) r.summary.push(`Envías ${sol(lamports)} a ${short(to)}.`);
  if (tokenTransfers >= 3) {
    r.add('sol-multi-drain', 'high', `Transfiere ${tokenTransfers} tokens distintos de tu wallet en una sola firma: así vacían wallets los drainers.`);
  } else if (tokenTransfers > 0 && solOut.size > 0 && recipients.size <= 2) {
    r.add('sol-multi-drain', 'medium', 'Envía SOL y tokens juntos a la misma dirección.');
  } else if (tokenTransfers + solOut.size > 0) {
    r.add('sol-transfer', 'none', 'Transferencia directa.');
  }
  const known = m.instructions.map((i) => PROGRAM_LABELS[i.programId]).filter((x): x is string => !!x && !x.startsWith('System') && !x.startsWith('SPL') && !x.startsWith('Compute') && !x.startsWith('Associated'));
  if (known.length) r.summary.push(`Usa ${[...new Set(known)].join(', ')}.`);
  if (unknown.size) {
    r.add('sol-unknown-program', 'low', `Interactúa con ${unknown.size} programa(s) que WalletShield no reconoce: ${[...unknown].slice(0, 3).map(short).join(', ')}.`);
  }
  if (m.lookupTables > 0) {
    r.add('sol-lookup-tables', 'none', `Usa ${m.lookupTables} tabla(s) de direcciones: algunas cuentas no se pueden mostrar sin consultar la red.`);
  }
}

function analyzeMessageBytes(r: R, bytes: Uint8Array, input: SolInput): void {
  // ¿El "mensaje" es en realidad una transacción serializada?
  try {
    const m = parseMessage(bytes);
    if (m.instructions.length > 0 && m.staticKeys.length > 0) {
      r.title = 'Firma de un "mensaje" que es una transacción';
      r.add('sol-message-tx', 'high', 'Lo que se presenta como mensaje es una transacción de Solana serializada. Firmarlo podría autorizar movimientos de fondos.');
      return;
    }
  } catch {
    /* no es una transacción: seguir */
  }
  const text = bytesToText(bytes);
  if (text === null) {
    r.title = 'Firma de datos binarios';
    r.add('sol-text', 'medium', 'El mensaje no es texto legible: no se puede saber qué firmas.');
    return;
  }
  const siws = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^\s/]+) wants you to sign in with your Solana account:\n/.exec(text);
  if (siws) {
    const domain = siws[1]!.replace(/:\d+$/, '').toLowerCase();
    r.title = 'Iniciar sesión con Solana';
    r.summary.push(`Inicio de sesión en "${domain.slice(0, 80)}".`);
    if (domain !== input.pageHost.toLowerCase()) {
      r.add('sol-siws-mismatch', 'high', `El mensaje es para iniciar sesión en "${domain.slice(0, 80)}", pero estás en "${input.pageHost}".`);
    } else {
      r.add('sol-siws', 'none', 'Inicio de sesión para este mismo sitio.');
    }
    return;
  }
  r.title = 'Firma de un mensaje de texto';
  r.summary.push(`"${text.length > 280 ? `${text.slice(0, 280)}…` : text}"`);
  r.add('sol-text', 'low', 'Firmar texto no mueve fondos por sí solo. Lee el mensaje antes de firmar.');
}

export function analyzeSolanaRequest(method: string, params: readonly unknown[], input: SolInput): Analysis {
  const r = new R();
  const p = (params[0] ?? {}) as SolPayload;
  try {
    if (method === 'solana:signMessage') {
      const bytes = decode(p.message);
      if (!bytes) r.add('sol-text', 'high', 'No se pudo leer el mensaje a firmar.');
      else analyzeMessageBytes(r, bytes, input);
    } else if (method === 'solana:signIn') {
      const domain = typeof p.signIn?.domain === 'string' ? p.signIn.domain.toLowerCase() : null;
      r.title = 'Iniciar sesión con Solana';
      if (domain && domain.replace(/:\d+$/, '') !== input.pageHost.toLowerCase()) {
        r.add('sol-siws-mismatch', 'high', `El inicio de sesión es para "${domain.slice(0, 80)}", pero estás en "${input.pageHost}".`);
      } else {
        r.add('sol-siws', 'none', 'Inicio de sesión para este sitio.');
      }
    } else {
      const txs = Array.isArray(p.txs) ? p.txs.slice(0, 64) : [];
      if (txs.length === 0) r.add('sol-text', 'high', 'No se pudo leer la transacción.');
      const send = method.includes('AndSend');
      r.title = txs.length > 1 ? `Firmar ${txs.length} transacciones de Solana` : send ? 'Firmar y enviar una transacción de Solana' : 'Firmar una transacción de Solana';
      if (txs.length >= 5) r.add('sol-batch', 'medium', `Se firman ${txs.length} transacciones de una sola vez. Revisa que esperabas tantas.`);
      for (const t of txs) {
        const bytes = decode(t);
        if (!bytes) {
          r.add('sol-text', 'high', 'Una transacción no se pudo leer.');
          continue;
        }
        analyzeSolMessage(r, parseAny(bytes, t.wire === true));
      }
    }
  } catch (e) {
    r.add('sol-text', 'high', `No se pudo analizar: ${e instanceof SolParseError ? e.message : 'datos inválidos'}.`);
  }

  const harmless = r.findings.length > 0 && r.findings.every((f) => (f.code === 'sol-text' && f.risk === 'low') || f.code === 'sol-siws');
  if (riskAtLeast(input.siteRisk, 'medium') && !harmless) {
    r.add('suspicious-site', 'high', `Además, ${input.pageHost} parece imitar a un sitio conocido.`);
  }
  for (const t of input.pageThreats ?? []) {
    if (t.risk === 'high' || (t.risk === 'medium' && !harmless)) r.add('malicious-script', t.risk === 'high' ? 'high' : 'medium', `Esta página ${t.text}`);
  }
  return {
    method,
    risk: r.risk,
    title: r.title || 'Solicitud de Solana',
    summary: r.summary.slice(0, 40),
    findings: r.findings,
    hardBlockInStrict: r.findings.some((f) => f.code === 'sol-owner-change' || (f.code === 'sol-assign' && f.risk === 'high')),
  };
}
