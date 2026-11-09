// Prueba en el runtime real de Cloudflare (workerd vía `wrangler dev`), con
// RPC y Telegram simulados en un servidor local. No despliega nada.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { writeFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ME = '0x1111111111111111111111111111111111111111';
const DRAINER = '0xd4a1e2000000000000000000000000000000dead';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const pad = (a) => `0x${a.slice(2).padStart(64, '0')}`;
const state = { block: { eth: 1000, arb: 50000 }, logs: [], telegram: [] };

const mock = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    if (req.url.startsWith('/tg/')) {
      state.telegram.push({ path: req.url, ...JSON.parse(body) });
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"ok":true}');
    }
    const net = req.url.slice(1);
    const reqs = JSON.parse(body);
    const arr = Array.isArray(reqs) ? reqs : [reqs];
    const out = arr.map((r) => {
      let result = null;
      if (r.method === 'eth_blockNumber') result = `0x${state.block[net].toString(16)}`;
      if (r.method === 'eth_getTransactionCount') result = '0x5';
      if (r.method === 'eth_getLogs') result = net === 'eth' ? state.logs : [];
      return { jsonrpc: '2.0', id: r.id, result };
    });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(Array.isArray(reqs) ? out : out[0]));
  });
});
await new Promise((r) => mock.listen(0, '127.0.0.1', r));
const M = `http://127.0.0.1:${mock.address().port}`;

// Secretos de prueba para wrangler dev (archivo local, ignorado por git).
writeFileSync('.dev.vars', `TELEGRAM_BOT_TOKEN=000:prueba\nTELEGRAM_CHAT_ID=42\nTELEGRAM_API_BASE=${M}/tg\n`);
// Puerto libre elegido por el sistema.
const PORT = await new Promise((r) => { const t = createServer(); t.listen(0, '127.0.0.1', () => { const p = t.address().port; t.close(() => r(p)); }); });
const vars = { EVM_ADDRESSES: ME, ETH_RPC_URL: `${M}/eth`, ARB_RPC_URL: `${M}/arb` };
// Estado KV nuevo en cada prueba (wrangler dev lo persiste entre ejecuciones).
const persist = mkdtempSync(join(tmpdir(), 'ws-kv-'));
const args = ['wrangler', 'dev', '--test-scheduled', '--port', String(PORT), '--ip', '127.0.0.1', '--persist-to', persist, ...Object.entries(vars).flatMap(([k, v]) => ['--var', `${k}:${v}`])];
// Sin proxy: el worker solo habla con el servidor simulado local.
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(https?|all|no)_proxy$/i.test(k)));
// detached: se crea un grupo de procesos para poder cerrar también workerd al final.
const dev = spawn('npx', args, { env: { ...cleanEnv, WRANGLER_SEND_METRICS: 'false' }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
let logs = '';
dev.stdout.on('data', (d) => (logs += d));
dev.stderr.on('data', (d) => (logs += d));

const results = [];
const check = (n, ok, d = '') => { results.push(ok); console.log(`${ok ? '✔' : '✘'} ${n}${d ? `  (${d})` : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function trigger() {
  const r = await fetch(`http://127.0.0.1:${PORT}/__scheduled?cron=*/10+*+*+*+*`);
  await sleep(1500);
  return r.status;
}

try {
  let up = false;
  for (let i = 0; i < 90 && !up; i++) {
    await sleep(1000);
    up = await fetch(`http://127.0.0.1:${PORT}/`).then((r) => r.ok).catch(() => false);
  }
  check('el worker arranca en workerd (wrangler dev)', up, up ? '' : logs.slice(-500));
  const home = await (await fetch(`http://127.0.0.1:${PORT}/`)).text();
  check('la URL pública no expone direcciones ni estado', home.trim() === 'WalletShield monitor activo.' && !home.includes('0x'));

  check('cron #1 (línea base) se ejecuta', (await trigger()) === 200);
  check('Telegram recibe "monitor activo"', state.telegram.some((m) => /Monitor activo/.test(m.text)), `${state.telegram.length} mensajes`);
  check('el token va solo en la ruta del bot de Telegram', state.telegram.every((m) => m.path === '/tg/bot000:prueba/sendMessage' && m.chat_id === '42'));

  state.block.eth = 1040;
  state.logs = [{ address: USDC, topics: ['0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925', pad(ME), pad(DRAINER)], data: '0x' + 'f'.repeat(64), transactionHash: '0xfeed' }];
  await trigger();
  const last = state.telegram.at(-1)?.text ?? '';
  check('cron #2: alerta de aprobación ILIMITADA a un drainer', /RIESGO ALTO/.test(last) && /ILIMITADO de USDC/.test(last) && last.includes('revoke.cash/address/' + ME), last.slice(0, 120));
  // Se ignora el aviso de wrangler al no poder descargar Request.cf (herramienta local, sin red aquí).
  const workerLogs = logs.split('\n').filter((l) => !/Request\.cf|Request was cancelled|node:internal|undici|^\s+at /.test(l)).join('\n');
  check('sin errores del worker en los logs', !/\[walletshield\]|Uncaught|exception/i.test(workerLogs), workerLogs.match(/.*(\[walletshield\]|Uncaught|exception).*/i)?.[0] ?? '');
} catch (e) {
  check('ejecución', false, e.message);
} finally {
  if (process.env.WS_DEBUG) console.log('--- LOGS ---\n' + logs);
  try { process.kill(-dev.pid, 'SIGTERM'); } catch { dev.kill('SIGTERM'); }
  mock.close();
  rmSync('.dev.vars', { force: true });
  rmSync(persist, { recursive: true, force: true });
}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} verificaciones OK`);
setTimeout(() => process.exit(failed ? 1 : 0), 500);
