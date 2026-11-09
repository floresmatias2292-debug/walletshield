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
import { parseSettings, type Settings } from '../../shared/settings';
import { riskAtLeast, type RiskLevel } from '../../shared/risk';
import { toBigInt } from '../../shared/evm/hex';
import { resolveLookups, type Rpc } from './lookups';
import { askUser } from './modal';

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

// ── ajustes y datos (se cargan una vez, con caché) ─────────────────────────
let settings: Settings | null = null;
let badAddresses: Set<string> | null = null;
async function getSettings(): Promise<Settings> {
  if (!settings) settings = parseSettings((await chrome.storage.local.get('settings')).settings);
  return settings;
}
async function getBadAddresses(): Promise<Set<string>> {
  if (!badAddresses) {
    const { badAddresses: list } = await chrome.storage.local.get('badAddresses');
    badAddresses = new Set(Array.isArray(list) ? (list as string[]).filter((x) => typeof x === 'string') : []);
  }
  return badAddresses;
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.settings) settings = null;
  if (changes.badAddresses) badAddresses = null;
});

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

function report(kind: 'fw-block' | 'fw-allow' | 'fw-auto-block', a: Analysis, host: string): void {
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

async function onMain(raw: unknown): Promise<void> {
  const msg = parseMainToIso(raw);
  if (!msg) return;
  if (msg.t === 'rpc-res') {
    rpcPending.get(msg.id)?.({ ok: msg.ok, result: msg.result });
    rpcPending.delete(msg.id);
    return;
  }
  port?.postMessage({ t: 'ack', id: msg.id });
  try {
    decide(msg.id, await evaluate(msg.id, msg.method, msg.params, msg.frame));
  } catch {
    decide(msg.id, false); // ante cualquier error: falla cerrado
  }
}

async function evaluate(id: number, method: string, params: unknown[], frame: FrameInfo): Promise<boolean> {
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
    return false;
  }

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

  const lookups = lookupsFor(method, params, input);
  if (lookups.length) input.answers = await resolveLookups(rpc, lookups);

  const analysis = analyzeRequest(method, params, input);

  if (!riskAtLeast(analysis.risk, modalThreshold(s.strictness)) || analysis.risk === 'none') {
    return true;
  }
  const hardBlock = s.strictness === 'strict' && analysis.hardBlockInStrict;
  const allow = await askUser({ analysis, host, hardBlock, technical: technicalDump(method, params) });
  report(allow ? 'fw-allow' : hardBlock ? 'fw-auto-block' : 'fw-block', analysis, host);
  return allow && !hardBlock;
}

function baseInput(host: string, chainId: number | null, account: string | null, bad: Set<string>): AnalysisInput & { answers: Map<string, unknown> } {
  return { chainId, account, pageHost: host, siteRisk: siteRisk(host), now: Date.now(), badAddresses: bad, answers: new Map() };
}
