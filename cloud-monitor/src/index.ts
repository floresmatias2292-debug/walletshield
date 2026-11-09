/**
 * WalletShield — monitor en la nube.
 * Cloudflare Worker con Cron Trigger: revisa direcciones PÚBLICAS de Ethereum,
 * Arbitrum y Solana, y avisa por Telegram ante aprobaciones nuevas,
 * transferencias salientes y cambios de autoridad.
 */
import { ConfigError, loadConfig, type Config } from './config';
import { scanChain } from './evm';
import { scanSolana } from './solana';
import { loadState, saveState, type State } from './state';
import { formatAlerts, sendTelegram } from './telegram';
import type { Alert, Env, Severity } from './types';

const FAILURES_TO_ALERT = 3;
const MAX_PENDING = 50;
const ORDER: Record<Severity, number> = { alta: 0, media: 1, info: 2 };

export interface RunReport {
  readonly alerts: number;
  readonly sent: number;
  readonly errors: string[];
  readonly baseline: boolean;
}

/** Una ejecución completa. Exportada para tests. */
export async function runMonitor(env: Env, fetchImpl: typeof fetch = fetch, now = Date.now()): Promise<RunReport> {
  let cfg: Config;
  try {
    cfg = loadConfig(env);
  } catch (e) {
    const msg = e instanceof ConfigError ? e.message : 'configuración inválida';
    console.error(`[walletshield] ${msg}`);
    return { alerts: 0, sent: 0, errors: [msg], baseline: false };
  }
  const state: State = await loadState(env.STATE);
  const firstRun = state.lastRun === 0;
  const alerts: Alert[] = [];
  const errors: string[] = [];

  // EVM: cadenas en paralelo
  const evmResults = await Promise.allSettled(cfg.chains.map((c) => scanChain(c, cfg.evm, state.evm[String(c.id)], fetchImpl)));
  evmResults.forEach((r, i) => {
    const c = cfg.chains[i]!;
    const key = String(c.id);
    if (r.status === 'fulfilled') {
      alerts.push(...r.value.alerts);
      state.evm[key] = r.value.state;
    } else {
      const prev = state.evm[key];
      const failures = (prev?.failures ?? 0) + 1;
      if (prev) state.evm[key] = { ...prev, failures };
      const reason = r.reason instanceof Error ? r.reason.message : String(r.reason);
      errors.push(`${c.name}: ${reason}`);
      if (failures === FAILURES_TO_ALERT) {
        alerts.push({ severity: 'media', chain: c.name, address: cfg.evm[0] ?? '', text: `No pude revisar ${c.name} en las últimas ${FAILURES_TO_ALERT} ejecuciones (${reason}). Revisa el RPC configurado.` });
      }
    }
  });

  // Solana: una dirección a la vez (los RPC públicos limitan la frecuencia)
  for (const addr of cfg.solana) {
    const prev = state.sol[addr];
    try {
      const r = await scanSolana(cfg.solRpc, addr, prev === undefined ? undefined : prev.lastSig, fetchImpl);
      alerts.push(...r.alerts);
      state.sol[addr] = { lastSig: r.lastSig, failures: 0 };
    } catch (e) {
      const failures = (prev?.failures ?? 0) + 1;
      if (prev) state.sol[addr] = { ...prev, failures };
      const reason = e instanceof Error ? e.message : String(e);
      errors.push(`Solana: ${reason}`);
      if (failures === FAILURES_TO_ALERT) alerts.push({ severity: 'media', chain: 'Solana', address: addr, text: `No pude revisar Solana en las últimas ${FAILURES_TO_ALERT} ejecuciones (${reason}).` });
    }
  }

  // Filtro por nivel y alertas pendientes de ejecuciones anteriores (si Telegram falló)
  const level = (['alta', 'media', 'info'] as const).find((l) => l === env.NOTIFY_LEVEL) ?? 'info';
  const pending = state.pending;
  const toSend = [...pending, ...alerts.filter((a) => ORDER[a.severity] <= ORDER[level])];

  if (firstRun && cfg.telegram) {
    const chains = [...cfg.chains.map((c) => c.name), ...(cfg.solana.length ? ['Solana'] : [])].join(', ');
    toSend.unshift({ severity: 'info', chain: 'WalletShield', address: '', text: `Monitor activo: vigilando ${cfg.evm.length + cfg.solana.length} dirección(es) en ${chains} cada 10 minutos.` });
  }

  let sent = 0;
  let stillPending: Alert[] = [];
  if (toSend.length && cfg.telegram) {
    try {
      for (const m of formatAlerts(toSend)) {
        await sendTelegram(cfg.telegram, m, fetchImpl);
        sent++;
      }
    } catch (e) {
      errors.push(e instanceof Error ? e.message : 'Telegram falló');
      stillPending = toSend.filter((a) => a.chain !== 'WalletShield').slice(-MAX_PENDING);
    }
  } else if (toSend.length) {
    errors.push('Telegram no configurado: define los secrets TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID');
    stillPending = toSend.slice(-MAX_PENDING);
  }

  state.pending = stillPending;
  state.lastRun = now;
  await saveState(env.STATE, state);
  if (errors.length) console.warn(`[walletshield] ${errors.join(' | ')}`);
  return { alerts: alerts.length, sent, errors, baseline: firstRun };
}

export default {
  async scheduled(_event: unknown, env: Env, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<void> {
    ctx.waitUntil(runMonitor(env));
  },
  // Respuesta mínima: no expone direcciones ni estado.
  async fetch(): Promise<Response> {
    return new Response('WalletShield monitor activo.\n', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
  },
};
