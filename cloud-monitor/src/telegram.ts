/** Formato y envío de alertas por Telegram (Bot API, parse_mode HTML). */
import type { Alert, Severity } from './types';

const MAX_LEN = 3800;
const ORDER: Record<Severity, number> = { alta: 0, media: 1, info: 2 };
const ICON: Record<Severity, string> = { alta: '🚨', media: '⚠️', info: 'ℹ️' };

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const short = (a: string) => (a.startsWith('0x') ? `${a.slice(0, 6)}…${a.slice(-4)}` : `${a.slice(0, 4)}…${a.slice(-4)}`);

/** Agrupa por dirección y cadena; devuelve uno o más mensajes de hasta ~3800 caracteres. */
export function formatAlerts(alerts: readonly Alert[]): string[] {
  if (!alerts.length) return [];
  const groups = new Map<string, Alert[]>();
  for (const a of [...alerts].sort((x, y) => ORDER[x.severity] - ORDER[y.severity])) {
    const k = `${a.chain}|${a.address}`;
    groups.set(k, [...(groups.get(k) ?? []), a]);
  }
  const worst = alerts.reduce<Severity>((w, a) => (ORDER[a.severity] < ORDER[w] ? a.severity : w), 'info');
  const header = worst === 'alta' ? '🚨 <b>WalletShield: actividad de RIESGO ALTO</b>' : worst === 'media' ? '⚠️ <b>WalletShield: actividad en tus direcciones</b>' : 'ℹ️ <b>WalletShield</b>';
  const blocks: string[] = [];
  for (const [k, list] of groups) {
    const [chain, address] = k.split('|') as [string, string];
    const lines = [`\n<b>${escapeHtml(chain)}</b> · <code>${escapeHtml(short(address))}</code>`];
    for (const a of list.slice(0, 25)) {
      const link = a.link ? ` <a href="${escapeHtml(a.link)}">ver</a>` : '';
      lines.push(`${ICON[a.severity]} ${escapeHtml(a.text)}${link}`);
    }
    if (list.length > 25) lines.push(`… y ${list.length - 25} eventos más.`);
    const revoke = list.find((a) => a.revoke)?.revoke;
    if (revoke) lines.push(`👉 Revisa y revoca permisos: <a href="${escapeHtml(revoke)}">revoke.cash</a>`);
    else if (chain === 'Solana' && list.some((a) => a.severity !== 'info')) {
      lines.push(`👉 Revisa tus cuentas: <a href="https://solscan.io/account/${escapeHtml(address)}">Solscan</a>. Revoca delegaciones desde tu wallet.`);
    }
    blocks.push(lines.join('\n'));
  }
  const messages: string[] = [];
  let cur = header;
  for (const b of blocks) {
    if (cur.length + b.length > MAX_LEN) {
      messages.push(cur);
      cur = `${header} (cont.)`;
    }
    cur += `\n${b.length > MAX_LEN ? `${b.slice(0, MAX_LEN - 20)}…` : b}`;
  }
  messages.push(cur);
  return messages;
}

export async function sendTelegram(cfg: { token: string; chatId: string; base: string }, text: string, fetchImpl: typeof fetch = fetch): Promise<void> {
  const url = `${cfg.base}/bot${cfg.token}/sendMessage`;
  const body = JSON.stringify({ chat_id: cfg.chatId, text, parse_mode: 'HTML', disable_web_page_preview: true });
  for (let attempt = 0; attempt < 2; attempt++) {
    const res = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body, signal: AbortSignal.timeout(10_000) });
    if (res.ok) return;
    if (res.status === 429 && attempt === 0) {
      const j = (await res.json().catch(() => ({}))) as { parameters?: { retry_after?: number } };
      await new Promise((r) => setTimeout(r, Math.min(5, j.parameters?.retry_after ?? 1) * 1000));
      continue;
    }
    // Nunca se incluye la URL (contiene el token) en el error.
    throw new Error(`Telegram respondió ${res.status}`);
  }
}
