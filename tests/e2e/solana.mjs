// Test end-to-end de la fase 5: Phantom simulado (API legacy, Wallet Standard
// y provider EVM) con transacciones reales construidas con @solana/web3.js.
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const web3 = require('@solana/web3.js');
const spl = require('@solana/spl-token');
const bs58 = require('bs58').default ?? require('bs58');

// ── transacciones reales ───────────────────────────────────────────────────
const kp = (n) => web3.Keypair.fromSeed(new Uint8Array(32).fill(n));
const user = kp(1).publicKey;
const attacker = kp(9).publicKey;
const blockhash = bs58.encode(new Uint8Array(32).fill(7));
const msgOf = (...ixs) => new web3.Transaction({ feePayer: user, recentBlockhash: blockhash }).add(...ixs).serializeMessage();
const b64 = (u) => Buffer.from(u).toString('base64');
const DRAIN = msgOf(spl.createSetAuthorityInstruction(kp(21).publicKey, user, spl.AuthorityType.AccountOwner, attacker));
const BENIGN = msgOf(web3.SystemProgram.transfer({ fromPubkey: user, toPubkey: attacker, lamports: 10_000_000 }));
const DRAIN_WIRE = new web3.VersionedTransaction(
  new web3.TransactionMessage({ payerKey: user, recentBlockhash: blockhash, instructions: [web3.SystemProgram.assign({ accountPubkey: user, programId: attacker })] }).compileToV0Message(),
).serialize();
const BENIGN_WIRE = new web3.VersionedTransaction(
  new web3.TransactionMessage({ payerKey: user, recentBlockhash: blockhash, instructions: [web3.SystemProgram.transfer({ fromPubkey: user, toPubkey: attacker, lamports: 1000 })] }).compileToV0Message(),
).serialize();

// ── servidor y navegador ───────────────────────────────────────────────────
const SITE = resolve('tests/e2e/site');
const http = createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const file = u.pathname === '/' ? 'solana.html' : u.pathname.slice(1);
  if (!/^[\w.-]+$/.test(file)) { res.writeHead(404); return res.end(); }
  try {
    const body = readFileSync(join(SITE, file), 'utf8');
    res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : 'text/html; charset=utf-8' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise((r) => http.listen(0, '127.0.0.1', r));
const ext = resolve('dist');
const ctx = await chromium.launchPersistentContext(join(mkdtempSync(join(tmpdir(), 'ws-sol-')), 'p'), {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-proxy-server', `--host-resolver-rules=MAP * 127.0.0.1:${http.address().port}`],
});

const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? '✔' : '✘'} ${name}${detail ? `  (${detail})` : ''}`); };
const modalOpen = (page) => page.evaluate(() => [...document.documentElement.children].some((e) => (e.getAttribute('style') ?? '').includes('inset: 0')));
async function waitModal(page, ms = 4000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await modalOpen(page)) return true; await page.waitForTimeout(50); } return false; }
const calls = (page) => page.evaluate(() => window.__solCalls.slice());
const reset = (page) => page.evaluate(() => { window.__solCalls.length = 0; });

try {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
  const page = await ctx.newPage();
  await page.goto('http://app.example-sol.com/');
  await page.waitForFunction(() => typeof window.__legacyTx === 'function');

  // 1. Latencia de una transacción benigna por la API legacy.
  const bench = await page.evaluate(([b]) => window.__bench(b, 30), [b64(BENIGN)]);
  check('transacción benigna pasa sin modal con < 5 ms extra', !(await modalOpen(page)) && bench.proxyMs - bench.rawMs < 5, `${(bench.proxyMs - bench.rawMs).toFixed(2)} ms`);

  // 2. Drainer por window.phantom.solana.signTransaction.
  await reset(page);
  let pending = page.evaluate(([b]) => window.__legacyTx(b, 'phantom'), [b64(DRAIN)]);
  check('Phantom legacy: SetAuthority (cambio de dueño) → modal', await waitModal(page));
  await page.keyboard.press('Enter');
  let r = await pending;
  check('…bloqueado: Phantom nunca recibe la transacción', !r.ok && (await calls(page)).length === 0, r.message);

  // 3. window.solana con transacción benigna.
  r = await page.evaluate(([b]) => window.__legacyTx(b, 'solana'), [b64(BENIGN)]);
  check('window.solana: transferencia pequeña pasa', r.ok && (await calls(page)).some((c) => c.startsWith('signTransaction')));

  // 4. Wallet Standard (wallet-adapter): drainer "owner change" en v0.
  check('Wallet Standard: la dapp ve la wallet registrada', (await page.evaluate(() => window.__stdCount())) >= 1);
  await reset(page);
  pending = page.evaluate(([b]) => window.__stdTx(b, false), [b64(DRAIN_WIRE)]);
  check('Wallet Standard: System Assign de tu wallet → modal', await waitModal(page));
  await page.keyboard.press('Escape');
  r = await pending;
  check('…bloqueado', !r.ok && (await calls(page)).length === 0);

  // 5. Wallet Standard benigna + la página muta los bytes después de llamar.
  await reset(page);
  r = await page.evaluate(([b]) => window.__stdTx(b, true), [b64(BENIGN_WIRE)]);
  const got = (await calls(page)).find((c) => c.startsWith('std:signTransaction:'));
  check('Wallet Standard: la wallet recibe exactamente los bytes analizados (copia protegida)', r.ok && got === 'std:signTransaction:' + Buffer.from(BENIGN_WIRE).toString('hex').slice(0, 16), got);

  // 6. Mensajes.
  r = await page.evaluate(() => window.__stdMsg('Iniciar sesión en Example. Nonce 9'));
  check('signMessage de texto pasa sin modal', r.ok && !(await modalOpen(page)));
  pending = page.evaluate(([b]) => window.__legacyMsg(b), [b64(DRAIN)]);
  check('signMessage con una transacción disfrazada → modal', await waitModal(page));
  await page.keyboard.press('Enter');
  check('…bloqueado', !(await pending).ok);

  // 7. Phantom request() con base58.
  await reset(page);
  pending = page.evaluate(([m]) => window.__request('signAndSendTransaction', m), [bs58.encode(DRAIN)]);
  check('Phantom request({signAndSendTransaction}) → modal', await waitModal(page));
  await page.keyboard.press('Enter');
  r = await pending;
  check('…bloqueado', !r.ok && (await calls(page)).length === 0);

  // 8. Tras 4 intentos de drainer en un minuto, la página quedó marcada como maliciosa (ráfaga):
  //    hasta una transacción inocente pide confirmación.
  pending = page.evaluate(([b]) => window.__legacyTx(b, 'phantom'), [b64(BENIGN)]);
  check('ráfaga de drainers: la página queda marcada y todo pide confirmación', await waitModal(page));
  await page.keyboard.press('Enter');
  await pending;

  // 9. TOCTOU (página nueva): el objeto cambia la transacción después del análisis.
  const p2 = await ctx.newPage();
  await p2.goto('http://app.example-sol.com/');
  await p2.waitForFunction(() => typeof window.__toctou === 'function');
  r = await p2.evaluate(([g, b]) => window.__toctou(g, b), [b64(BENIGN), b64(DRAIN)]);
  check('transacción que cambia después del análisis: bloqueada', !r.ok && (await calls(p2)).length === 0, r.message);

  // 10. Provider EVM de Phantom.
  pending = p2.evaluate(() => window.__phantomEth());
  check('window.phantom.ethereum también pasa por el firewall EVM', await waitModal(p2));
  await p2.keyboard.press('Enter');
  check('…bloqueado', !(await pending).ok && !(await calls(p2)).some((c) => c.startsWith('eth:eth_sign')));
  console.log(`\nLatencia signTransaction: ${bench.rawMs.toFixed(3)} → ${bench.proxyMs.toFixed(3)} ms`);
} catch (e) {
  check('ejecución', false, e.stack);
} finally {
  await ctx.close();
  http.close();
}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} verificaciones OK`);
process.exit(failed ? 1 : 0);
