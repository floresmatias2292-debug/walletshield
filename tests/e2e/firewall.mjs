// Test end-to-end del firewall de wallets: dapp + wallet simulada en Chromium
// real con la extensión cargada. Verifica bloqueo, modal, intentos de evasión
// y la latencia añadida.
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const { chromium } = createRequire(import.meta.url)('playwright');
const SITE = resolve('tests/e2e/site');

const http = createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const file = u.pathname === '/' ? 'dapp.html' : u.pathname.slice(1);
  if (!/^[\w.-]+$/.test(file)) { res.writeHead(404); return res.end(); }
  try {
    let body = readFileSync(join(SITE, file), 'utf8');
    if (file === 'dapp.html') body = body.replace('MODE', u.searchParams.get('mode') ?? 'assign');
    res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : 'text/html; charset=utf-8' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise((r) => http.listen(0, '127.0.0.1', r));
const PORT = http.address().port;

const USER = '0x1111111111111111111111111111111111111111';
const DRAINER_EOA = '0xd4a1e2000000000000000000000000000000dead';
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const UR_V2 = '0x66a9893cc07d91d95644aedd05d03f95e1dba8af';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const MAX160 = ((1n << 160n) - 1n).toString();
const now = Math.floor(Date.now() / 1000);
const drainerPermit = JSON.stringify({
  types: {}, primaryType: 'PermitBatch', domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
  message: { details: [USDC, '0xdAC17F958D2ee523a2206206994597C13D831ec7'].map((token) => ({ token, amount: MAX160, expiration: '281474976710655', nonce: '0' })), spender: DRAINER_EOA, sigDeadline: String(now + 3600) },
});
const uniswapPermit = JSON.stringify({
  types: {}, primaryType: 'PermitSingle', domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
  message: { details: { token: USDC, amount: MAX160, expiration: String(now + 30 * 86400), nonce: '1' }, spender: UR_V2, sigDeadline: String(now + 1800) },
});
const setApprovalForAll = { from: USER, to: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D', data: '0xa22cb465' + DRAINER_EOA.slice(2).padStart(64, '0') + '1'.padStart(64, '0') };

const work = mkdtempSync(join(tmpdir(), 'ws-fw-'));
const ext = resolve('dist');
const ctx = await chromium.launchPersistentContext(join(work, 'profile'), {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-proxy-server', `--host-resolver-rules=MAP * 127.0.0.1:${PORT}`],
});

const results = [];
const check = (name, ok, detail = '') => {
  results.push(ok);
  console.log(`${ok ? '✔' : '✘'} ${name}${detail ? `  (${detail})` : ''}`);
};

const modalOpen = (page) => page.evaluate(() => [...document.documentElement.children].some((e) => (e.getAttribute('style') ?? '').includes('2147483647')));
async function waitModal(page, ms = 4000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (await modalOpen(page)) return true;
    await page.waitForTimeout(50);
  }
  return false;
}
const walletGot = (page, method) => page.evaluate((m) => window.__walletCalls.includes(m), method);
const resetCalls = (page) => page.evaluate(() => { window.__walletCalls.length = 0; });

try {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
  const page = await ctx.newPage();
  await page.goto('http://app.example-dapp.com/?mode=assign');
  await page.waitForFunction(() => typeof window.__req === 'function');

  // 1. Latencia de llamadas no sensibles (la gran mayoría).
  const b1 = await page.evaluate(() => window.__bench(2000, 'eth_chainId', []));
  const extra1 = b1.proxyMs - b1.rawMs;
  check('lecturas (eth_chainId) pasan con < 0,05 ms extra', extra1 < 0.05, `${(extra1 * 1000).toFixed(1)} µs por llamada`);

  // 2. Firma de bajo riesgo (sin modal): latencia total añadida.
  const hex = '0x' + Buffer.from('Login en Example Dapp. Nonce: 8f3a').toString('hex');
  const b2 = await page.evaluate((h) => window.__bench(50, 'personal_sign', [h, '0x1111111111111111111111111111111111111111']), hex);
  const extra2 = b2.proxyMs - b2.rawMs;
  check('firma de bajo riesgo pasa sin modal y con < 5 ms extra', extra2 < 5 && !(await modalOpen(page)), `${extra2.toFixed(2)} ms`);

  // 3. Uniswap legítimo: sin modal y llega a la wallet.
  await resetCalls(page);
  let r = await page.evaluate((d) => window.__req('window', 'eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), uniswapPermit);
  check('Permit2 de Uniswap (Universal Router) pasa sin modal', r.ok && (await walletGot(page, 'eth_signTypedData_v4')));

  // 4. Drainer Permit2 → modal → Enter (foco en "Bloquear") → bloqueado.
  await resetCalls(page);
  let pending = page.evaluate((d) => window.__req('window', 'eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), drainerPermit);
  check('drainer Permit2: aparece el modal', await waitModal(page));
  await page.keyboard.press('Enter');
  r = await pending;
  check('Enter = Bloquear: la wallet nunca recibe la firma', !r.ok && r.code === 4001 && !(await walletGot(page, 'eth_signTypedData_v4')), `code=${r.code}`);
  check('el mensaje de error es claro', /WalletShield bloqueó/.test(r.message ?? ''), r.message);

  // 5. Mismo drainer por EIP-6963 → Escape → bloqueado.
  pending = page.evaluate((d) => window.__req('6963', 'eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), drainerPermit);
  check('EIP-6963: el provider anunciado también está protegido', await waitModal(page));
  await page.keyboard.press('Escape');
  r = await pending;
  check('Escape = Bloquear', !r.ok && !(await walletGot(page, 'eth_signTypedData_v4')));

  // 6. Evasiones: sendAsync, método interno _rpcRequest, provider devuelto por .on()
  pending = page.evaluate(() => window.__sendAsync('eth_sign', ['0x1111111111111111111111111111111111111111', '0x' + 'ab'.repeat(32)]));
  check('evasión por sendAsync interceptada', await waitModal(page));
  await page.keyboard.press('Enter');
  r = await pending;
  check('sendAsync bloqueado devuelve error al callback', !r.ok && !(await walletGot(page, 'eth_sign')));

  pending = page.evaluate((d) => window.__internal('eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), drainerPermit);
  check('evasión por método interno (_rpcRequest) interceptada', await waitModal(page));
  await page.keyboard.press('Enter');
  r = await pending;
  check('método interno bloqueado', !r.ok && !(await walletGot(page, 'eth_signTypedData_v4')));

  pending = page.evaluate((d) => window.__req('chained', 'eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), drainerPermit);
  check('evasión por el objeto que devuelve .on() interceptada', await waitModal(page));
  await page.keyboard.press('Enter');
  await pending;

  // 7. La página borra el modal → bloqueado.
  pending = page.evaluate((d) => window.__req('window', 'eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), drainerPermit);
  await waitModal(page);
  await page.evaluate(() => [...document.documentElement.children].filter((e) => (e.getAttribute('style') ?? '').includes('2147483647')).forEach((e) => e.remove()));
  r = await pending;
  check('si la página elimina el modal, se bloquea', !r.ok && !(await walletGot(page, 'eth_signTypedData_v4')));

  // 8. setApprovalForAll a cuenta personal → el usuario elige continuar (checkbox + espera).
  await resetCalls(page);
  pending = page.evaluate((tx) => window.__req('window', 'eth_sendTransaction', [tx]), setApprovalForAll);
  await waitModal(page);
  await page.keyboard.press('Enter'); // intento inmediato: Enter está en "Bloquear"
  r = await pending;
  check('setApprovalForAll a cuenta personal: bloqueado por defecto', !r.ok);
  pending = page.evaluate((tx) => window.__req('window', 'eth_sendTransaction', [tx]), setApprovalForAll);
  await waitModal(page);
  await page.keyboard.press('Shift+Tab'); // checkbox "Entiendo..."
  await page.keyboard.press('Space');
  await page.keyboard.press('Tab'); // Bloquear
  await page.keyboard.press('Tab'); // Continuar
  await page.waitForTimeout(1700);
  await page.keyboard.press('Enter');
  r = await pending;
  check('"Continuar de todos modos" (con confirmación) deja pasar', r.ok && (await walletGot(page, 'eth_sendTransaction')));

  // 9. El handshake falso de la página no recibió nada.
  check('canal privado: el puerto falso de la página no recibió mensajes', (await page.evaluate(() => window.__fakeGot)) === 0);

  // 10. Iframe oculto pidiendo una firma → bloqueo automático, sin modal.
  await page.evaluate(() => { document.getElementById('hidden').src = '/frame.html'; });
  const frame = await (async () => {
    for (let i = 0; i < 50; i++) {
      const f = page.frames().find((x) => x.url().endsWith('/frame.html'));
      if (f) { try { await f.waitForFunction(() => typeof window.__req === 'function', null, { timeout: 2000 }); return f; } catch { /* reintento */ } }
      await page.waitForTimeout(100);
    }
    return null;
  })();
  r = frame ? await frame.evaluate((d) => window.__req('window', 'eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), drainerPermit) : { ok: true };
  check('iframe oculto de 1×1 px: bloqueado sin preguntar', !r.ok && !(await modalOpen(page)));

  // 11. Wallet que se instala con defineProperty no configurable (estilo Rabby).
  const p2 = await ctx.newPage();
  await p2.goto('http://app.example-dapp.com/?mode=define');
  await p2.waitForFunction(() => typeof window.__req === 'function');
  pending = p2.evaluate((d) => window.__req('window', 'eth_signTypedData_v4', ['0x1111111111111111111111111111111111111111', d]), drainerPermit);
  check('wallet instalada con defineProperty(configurable:false): protegida', await waitModal(p2));
  await p2.keyboard.press('Enter');
  await pending;

  // 12. Modo estricto: eth_sign se bloquea sin opción de continuar.
  await sw.evaluate(async () => {
    const { settings } = await chrome.storage.local.get('settings');
    await chrome.storage.local.set({ settings: { ...(settings ?? {}), strictness: 'strict' } });
  });
  await p2.waitForTimeout(200);
  pending = p2.evaluate(() => window.__req('window', 'eth_sign', ['0x1111111111111111111111111111111111111111', '0x' + 'cd'.repeat(32)]));
  const strictModal = await waitModal(p2);
  await p2.keyboard.press('Enter'); // único botón: "Cerrar"
  r = await pending;
  check('modo estricto: eth_sign bloqueado sin opción de continuar', strictModal && !r.ok && !(await p2.evaluate(() => window.__walletCalls.includes('eth_sign'))));

  // 13. Contador y registro en el service worker.
  await page.waitForTimeout(300);
  const stats = await sw.evaluate(async () => (await chrome.storage.local.get('stats')).stats);
  const events = await sw.evaluate(async () => ((await chrome.storage.local.get('events')).events ?? []).filter((e) => e.kind.startsWith('fw-')).length);
  check('bloqueos contados y registrados', (stats?.blockedToday ?? 0) >= 8 && events >= 9, `bloqueados hoy=${stats?.blockedToday}, eventos fw=${events}`);
  console.log(`\nLatencia: eth_chainId ${(b1.rawMs * 1000).toFixed(1)}→${(b1.proxyMs * 1000).toFixed(1)} µs · personal_sign ${b2.rawMs.toFixed(2)}→${b2.proxyMs.toFixed(2)} ms`);
} catch (e) {
  check('ejecución', false, e.stack);
} finally {
  await ctx.close();
  http.close();
}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} verificaciones OK`);
process.exit(failed ? 1 : 0);
