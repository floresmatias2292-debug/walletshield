/**
 * WalletShield — script aislado (world: ISOLATED, document_start).
 *
 * Recibe del script MAIN cada solicitud sensible a la wallet, la analiza
 * localmente (sin enviar nada a terceros) y decide: pasa, o muestra el modal
 * con "Bloquear" como opción por defecto.
 */
import { HANDSHAKE_KEY, parseMainToIso, type FrameInfo } from '../../shared/bridge';
import { analyzeRequest, lookupsFor, modalThreshold, type Analysis, type AnalysisInput } from '../../shared/evm';
import { DomainAnalyzer } from '../../shared/domain/typosquat';
import { hostnameFromUrl } from '../../shared/domain/normalize';
import type { ContentConfig } from '../../shared/settings';
import { riskAtLeast, type RiskLevel } from '../../shared/risk';
import { toBigInt } from '../../shared/evm/hex';
import { knownContract, TOKEN_DECIMALS } from '../../shared/evm/known';
import { formatUnits, shortAddr } from '../../shared/evm/format';
import { resolveLookups, type Rpc } from './lookups';
import { askUser } from './modal';
import { analyzeSolanaRequest } from '../../shared/solana/analyzer';
import { addThreat, noteRiskyRequest, pageThreats, THREAT_TEXT, type PageThreat } from './threats';
import { scanScripts, scheduleScan } from './script-scan';
import { installClipboardGuard } from './clipboard';
import { toast } from './toast';

let port: MessagePort | null = null;

// ── handshake: el primer puerto que llega (el del script MAIN, que corre antes
// que cualquier script de la página) es el único aceptado ──────────────────
addEventListener(
  'message',
  (ev: MessageEvent) => {
    if (port || ev.source !== window) return;
    const d = ev.data as Record<string, unknown> | null;
    if (!d || typeof d !== 'object' || d[HANDSHAKE_KEY] !== true || ev.ports.length !== 1) return;
    ev.stopImmediatePropagation();
    port = ev.ports[0]!;
    port.onmessage = (e) => void onMain(e.data);
  },
  true,
);

// ── configuración: se pide al service worker solo cuando hace falta ────────
// (el almacenamiento de la extensión no es accesible desde content scripts)
const DEFAULT_CONFIG: ContentConfig = { strictness: 'normal', firewall: true, clipboardGuard: true, simulation: false };
let configPromise: Promise<{ config: ContentConfig; bad: Set<string> }> | null = null;
function loadConfig(): Promise<{ config: ContentConfig; bad: Set<string> }> {
  configPromise ??= chrome.runtime
    .sendMessage({ type: 'cs:config' })
    .then((r: unknown) => {
      const o = (r ?? {}) as { config?: Partial<ContentConfig>; badAddresses?: unknown };
      const c = o.config ?? {};
      const config: ContentConfig = {
        strictness: c.strictness === 'relaxed' || c.strictness === 'strict' ? c.strictness : 'normal',
        firewall: c.firewall !== false,
        clipboardGuard: c.clipboardGuard !== false,
        simulation: c.simulation === true,
      };
      const bad = new Set(Array.isArray(o.badAddresses) ? (o.badAddresses as unknown[]).filter((x): x is string => typeof x === 'string') : []);
      return { config, bad };
    })
    .catch(() => ({ config: DEFAULT_CONFIG, bad: new Set<string>() }));
  return configPromise;
}
// El service worker avisa cuando cambian los ajustes (solo él puede enviar esto).
chrome.runtime.onMessage.addListener((msg: unknown, sender) => {
  if (sender.id === chrome.runtime.id && !sender.tab && (msg as { type?: unknown } | null)?.type === 'cs:invalidate') configPromise = null;
  return false;
});

async function getSettings(): Promise<ContentConfig> {
  return (await loadConfig()).config;
}
async function getBadAddresses(): Promise<Set<string>> {
  return (await loadConfig()).bad;
}

let domainAnalyzer: DomainAnalyzer | null = null;
function siteRisk(host: string): RiskLevel {
  domainAnalyzer ??= new DomainAnalyzer();
  return domainAnalyzer.analyze(host).risk;
}

// ── RPC de solo lectura a través de MAIN ──────────────────────────────────
let rpcSeq = 0;
const rpcPending = new Map<number, (r: { ok: boolean; result: unknown }) => void>();

function rpcFor(reqId: number): Rpc {
  return (method, params) =>
    new Promise((resolve, reject) => {
      if (!port) return reject(new Error('sin canal'));
      const id = ++rpcSeq;
      const timer = setTimeout(() => {
        rpcPending.delete(id);
        reject(new Error('timeout'));
      }, 2000);
      rpcPending.set(id, (r) => {
        clearTimeout(timer);
        if (r.ok) resolve(r.result);
        else reject(new Error('rpc'));
      });
      port.postMessage({ t: 'rpc', id, reqId, method, params });
    });
}

function decide(id: number, allow: boolean): void {
  port?.postMessage({ t: 'decision', id, allow });
}

function report(kind: 'fw-block' | 'fw-allow' | 'fw-auto-block' | 'fw-threat', a: Pick<Analysis, 'method' | 'risk' | 'findings'>, host: string): void {
  void chrome.runtime
    .sendMessage({ type: 'fw:event', kind, method: a.method, risk: a.risk, host, codes: a.findings.map((f) => f.code).slice(0, 8) })
    .catch(() => undefined);
}

function technicalDump(method: string, params: unknown[]): string {
  let s: string;
  try {
    s = JSON.stringify({ method, params }, null, 2);
  } catch {
    s = method;
  }
  return s.length > 4000 ? `${s.slice(0, 4000)}\n…` : s;
}

/** Registra una amenaza de la página, avisa al usuario y al service worker. */
function recordThreat(t: PageThreat, notify = true): void {
  if (!addThreat(t)) return;
  const host = hostnameFromUrl(location.href) ?? location.hostname;
  report('fw-threat', { method: t.id.slice(0, 64), risk: t.risk, findings: [{ code: 'malicious-script', risk: t.risk, text: t.text }] }, host);
  if (notify && t.risk === 'high') toast('Comportamiento sospechoso', `Esta página ${t.text} Desconfía de cualquier firma que te pida.`);
}

let scanScheduled = false;
async function maybeScan(): Promise<void> {
  if (scanScheduled) return;
  scanScheduled = true;
  const s = await getSettings();
  if (!s.firewall) return;
  scheduleScan((hits) => {
    for (const h of hits) recordThreat({ id: `script:${h.id}`, risk: h.risk, text: `contiene código sospechoso: ${h.text}` });
  });
}

// Listeners baratos; la guardia consulta su estado al service worker solo al
// enfocar un campo editable (no despierta al worker en cada carga de página).
installClipboardGuard((text) => recordThreat({ id: 'clipboard-paste', risk: 'high', text }, false));

async function onMain(raw: unknown): Promise<void> {
  const msg = parseMainToIso(raw);
  if (!msg) return;
  if (msg.t === 'rpc-res') {
    rpcPending.get(msg.id)?.({ ok: msg.ok, result: msg.result });
    rpcPending.delete(msg.id);
    return;
  }
  if (msg.t === 'threat') {
    const def = THREAT_TEXT[msg.kind];
    recordThreat({ id: msg.kind, risk: def.risk, text: def.text });
    return;
  }
  if (msg.t === 'used') {
    void maybeScan();
    return;
  }
  port?.postMessage({ t: 'ack', id: msg.id });
  try {
    decide(msg.id, await evaluate(msg.id, msg.method, msg.params, msg.frame, msg.ns));
  } catch {
    decide(msg.id, false); // ante cualquier error: falla cerrado
  }
}

async function evaluate(id: number, method: string, params: unknown[], frame: FrameInfo, ns: 'evm' | 'solana'): Promise<boolean> {
  const s = await getSettings();
  if (!s.firewall) return true;
  const host = hostnameFromUrl(location.href) ?? location.hostname;

  // Solicitud desde un iframe diminuto u oculto: patrón de drainers.
  if (!frame.top && (frame.w < 120 || frame.h < 80)) {
    const a: Analysis = {
      method,
      risk: 'high',
      title: 'Solicitud desde un marco oculto',
      summary: [],
      findings: [{ code: 'suspicious-site', risk: 'high', text: 'Un iframe invisible pidió una firma a tu wallet.' }],
      hardBlockInStrict: true,
    };
    report('fw-auto-block', a, host);
    toast('Firma bloqueada', 'Un marco invisible de esta página pidió una firma a tu wallet. Se bloqueó automáticamente.');
    return false;
  }

  if (ns === 'solana') return evaluateSolana(method, params, host, s);

  if (params.length === 1 && (params[0] as Record<string, unknown> | null)?.__walletshield_unreadable__) {
    const a = analyzeRequest(method, [null], baseInput(host, null, null, new Set()));
    return askUser({ analysis: { ...a, risk: 'high', title: 'Solicitud que no se pudo leer' }, host, hardBlock: false, technical: method });
  }

  const rpc = rpcFor(id);
  const [chainRaw, accounts, bad] = await Promise.all([
    rpc('eth_chainId', []).catch(() => null),
    rpc('eth_accounts', []).catch(() => null),
    getBadAddresses(),
  ]);
  const chainId = toBigInt(chainRaw);
  const account = Array.isArray(accounts) && typeof accounts[0] === 'string' ? accounts[0].toLowerCase() : null;
  const input = baseInput(host, chainId === null ? null : Number(chainId), account, bad);

  // Resultado del escaneo de scripts (si todavía corre, se espera un poco).
  void maybeScan();
  const hits = await Promise.race([scanScripts(), new Promise<null>((r) => setTimeout(() => r(null), 400))]);
  for (const h of hits ?? []) recordThreat({ id: `script:${h.id}`, risk: h.risk, text: `contiene código sospechoso: ${h.text}` }, false);
  input.pageThreats = pageThreats();

  const lookups = lookupsFor(method, params, input);
  if (lookups.length) input.answers = await resolveLookups(rpc, lookups);

  const analysis = analyzeRequest(method, params, input);

  if (!riskAtLeast(analysis.risk, modalThreshold(s.strictness)) || analysis.risk === 'none') {
    return true;
  }
  // Una página que insiste con solicitudes peligrosas se marca como maliciosa.
  if (analysis.risk === 'high' && noteRiskyRequest()) {
    const def = THREAT_TEXT['request-burst'];
    recordThreat({ id: 'request-burst', risk: def.risk, text: def.text }, false);
  }
  const hardBlock = s.strictness === 'strict' && analysis.hardBlockInStrict;
  let shown = analysis;
  if (s.simulation && !hardBlock && method === 'eth_sendTransaction' && chainId !== null) {
    shown = await withSimulation(analysis, params[0], Number(chainId), account, rpc);
  }
  const allow = await askUser({ analysis: shown, host, hardBlock, technical: technicalDump(method, params) });
  report(allow ? 'fw-allow' : hardBlock ? 'fw-auto-block' : 'fw-block', analysis, host);
  return allow && !hardBlock;
}

/** Agrega al modal el resultado (informativo) de la simulación con Tenderly. */
async function withSimulation(a: Analysis, rawTx: unknown, chainId: number, account: string | null, rpc: Rpc): Promise<Analysis> {
  const t = (rawTx ?? {}) as Record<string, unknown>;
  const from = typeof t.from === 'string' ? t.from : account;
  if (!from || typeof t.to !== 'string') return a;
  const block = toBigInt(await rpc('eth_blockNumber', []).catch(() => null));
  const r = (await chrome.runtime
    .sendMessage({
      type: 'sim:run',
      chainId,
      blockNumber: block === null ? null : Number(block),
      tx: { from, to: t.to, value: typeof t.value === 'string' ? t.value : '0x0', data: typeof t.data === 'string' ? t.data : '0x' },
    })
    .catch(() => null)) as { ok?: boolean; reverted?: boolean; error?: string; changes?: Array<{ kind: string; token: string; amount: string; counterparty: string }> } | null;
  if (!r) return a;
  if (!r.ok) return { ...a, summary: [...a.summary, `Simulación (Tenderly): no disponible — ${r.error ?? 'error'}.`] };
  const lines = (r.changes ?? []).map((c) => {
    const k = knownContract(c.token, chainId);
    const amount = /^\d+$/.test(c.amount) ? (BigInt(c.amount) >= 1n << 100n ? 'ILIMITADO' : formatUnits(BigInt(c.amount), k ? (TOKEN_DECIMALS[k.label] ?? null) : null)) : c.amount;
    const token = k?.label ?? shortAddr(c.token);
    return c.kind === 'out'
      ? `Simulación: salen ${amount} ${token} de tu wallet hacia ${shortAddr(c.counterparty)}.`
      : c.kind === 'in'
        ? `Simulación: entran ${amount} ${token} a tu wallet.`
        : `Simulación: queda aprobado ${amount} de ${token} para ${shortAddr(c.counterparty)}.`;
  });
  if (r.reverted) lines.push('Simulación: la transacción FALLARÍA (revert).');
  if (!lines.length) lines.push('Simulación: no se detectaron movimientos de tokens.');
  return { ...a, summary: [...a.summary, ...lines] };
}

/** Solana: el análisis es 100 % local (no hace falta consultar la red). */
async function evaluateSolana(method: string, params: unknown[], host: string, s: ContentConfig): Promise<boolean> {
  void maybeScan();
  const hits = await Promise.race([scanScripts(), new Promise<null>((r) => setTimeout(() => r(null), 400))]);
  for (const h of hits ?? []) recordThreat({ id: `script:${h.id}`, risk: h.risk, text: `contiene código sospechoso: ${h.text}` }, false);
  const unreadable = (params[0] as Record<string, unknown> | null)?.__walletshield_unreadable__ === true;
  let analysis = analyzeSolanaRequest(method, unreadable ? [{}] : params, { pageHost: host, siteRisk: siteRisk(host), pageThreats: pageThreats() });
  if (unreadable) analysis = { ...analysis, risk: 'high', title: 'Transacción de Solana que no se pudo leer' };
  if (analysis.risk === 'none' || !riskAtLeast(analysis.risk, modalThreshold(s.strictness))) return true;
  if (analysis.risk === 'high' && noteRiskyRequest()) {
    const def = THREAT_TEXT['request-burst'];
    recordThreat({ id: 'request-burst', risk: def.risk, text: def.text }, false);
  }
  const hardBlock = s.strictness === 'strict' && analysis.hardBlockInStrict;
  const allow = await askUser({ analysis, host, hardBlock, technical: technicalDump(method, params) });
  report(allow ? 'fw-allow' : hardBlock ? 'fw-auto-block' : 'fw-block', analysis, host);
  return allow && !hardBlock;
}

function baseInput(host: string, chainId: number | null, account: string | null, bad: Set<string>): AnalysisInput & { answers: Map<string, unknown> } {
  return { chainId, account, pageHost: host, siteRisk: siteRisk(host), pageThreats: pageThreats(), now: Date.now(), badAddresses: bad, answers: new Map() };
}
