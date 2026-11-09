// Test end-to-end de la fase 4: scripts maliciosos y portapapeles.
import { createRequire } from 'node:module';
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const { chromium } = createRequire(import.meta.url)('playwright');
const SITE = resolve('tests/e2e/site');
// HTTPS local: la API del portapapeles solo existe en contextos seguros.
const work = mkdtempSync(join(tmpdir(), 'ws-th-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
  '-keyout', join(work, 'k.pem'), '-out', join(work, 'c.pem')], { stdio: 'ignore' });
const http = createServer({ key: readFileSync(join(work, 'k.pem')), cert: readFileSync(join(work, 'c.pem')) }, (req, res) => {
  const u = new URL(req.url, 'http://x');
  const file = u.pathname === '/' ? 'threats.html' : u.pathname.slice(1);
  if (!/^[\w.-]+$/.test(file)) { res.writeHead(404); return res.end(); }
  try {
    const body = readFileSync(join(SITE, file), 'utf8').replace('MODE', 'assign');
    res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : 'text/html; charset=utf-8' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise((r) => http.listen(0, '127.0.0.1', r));

const ext = resolve('dist');
const ctx = await chromium.launchPersistentContext(join(work, 'p'), {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-proxy-server', '--ignore-certificate-errors', `--host-resolver-rules=MAP * 127.0.0.1:${http.address().port}`],
});
const ORIGIN = 'https://shop.example-dapp.com';
await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGIN });

const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? '✔' : '✘'} ${name}${detail ? `  (${detail})` : ''}`); };
const overlays = (page) => page.evaluate(() => [...document.documentElement.children].filter((e) => (e.getAttribute('style') ?? '').includes('2147483647')).length);
async function waitFor(fn, ms = 4000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 50)); } return false; }
const textHex = '0x' + Buffer.from('Login en la tienda. Nonce 42').toString('hex');
const USER = '0x1111111111111111111111111111111111111111';

async function open(attack) {
  const page = await ctx.newPage();
  await page.goto(`${ORIGIN}/?attack=${attack}`);
  await page.waitForFunction(() => typeof window.__req === 'function');
  return page;
}

try {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });

  // 0. Control: sin ataques, una firma de texto pasa sin modal.
  let page = await open('none');
  let r = await page.evaluate(([m, u]) => window.__req('window', 'personal_sign', [m, u]), [textHex, USER]);
  check('control: página limpia, firma de texto pasa sin modal', r.ok && (await overlays(page)) === 0);

  // 1. Script de la página reemplaza window.ethereum.
  page = await open('overwrite');
  await page.waitForTimeout(300);
  check('reemplazo de window.ethereum por la página: aviso visible', (await overlays(page)) >= 1);
  let pending = page.evaluate(([m, u]) => window.__req('window', 'personal_sign', [m, u]), [textHex, USER]);
  const modal1 = await waitFor(async () => (await overlays(page)) >= 2);
  check('después del reemplazo, hasta una firma de texto pide confirmación (riesgo alto)', modal1);
  await page.keyboard.press('Escape');
  r = await pending;
  check('…y se bloquea por defecto', !r.ok);

  // 2. Canal interno de la wallet.
  page = await open('none');
  await page.evaluate(() => { window.__channelAttack(); window.__channelBenign(); });
  await page.waitForTimeout(200);
  const got = await page.evaluate(() => window.__channelGot);
  check('mensaje eth_sign directo al canal de MetaMask: bloqueado', !got.includes('eth_sign'), JSON.stringify(got));
  check('mensajes no sensibles por ese canal siguen funcionando', got.includes('eth_chainId'));

  // 3. Kit de drainer detectado por firma de código.
  page = await open('drainer-kit');
  await page.evaluate(() => window.ethereum.request({ method: 'eth_chainId' })); // usa el provider → escaneo diferido
  await page.waitForTimeout(800);
  pending = page.evaluate(([m, u]) => window.__req('window', 'personal_sign', [m, u]), [textHex, USER]);
  check('kit de drainer (bot de Telegram + firmas): la firma inocua pasa a riesgo alto', await waitFor(async () => (await overlays(page)) >= 1));
  await page.keyboard.press('Enter');
  r = await pending;
  check('…y se bloquea', !r.ok);

  // 4. Clipper al copiar: se restaura la dirección original.
  page = await open('clipper');
  await page.evaluate(() => { const s = getSelection(); const rg = document.createRange(); rg.selectNodeContents(document.getElementById('addr')); s.removeAllRanges(); s.addRange(rg); });
  await page.keyboard.press('Control+C');
  await page.waitForTimeout(200);
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  check('la página cambió la dirección al copiar → se restauró la original', clip === '0x52908400098527886E0F7030069857D2E4169EE7', clip);

  // 5. Escritura silenciosa al portapapeles.
  // (page.evaluate de Playwright simula un gesto del usuario: el ataque corre solo al cargar.)
  page = await open('silent-clip');
  await page.waitForFunction(() => window.__silentRes !== undefined, null, { timeout: 9000 }).catch(() => undefined);
  const silent = await page.evaluate(() => window.__silentRes);
  check('escritura de dirección sin acción del usuario: bloqueada', silent === 'NotAllowedError', silent);
  await page.click('#copybtn');
  await page.waitForTimeout(200);
  check('botón "Copiar dirección" (clic real) sigue funcionando', (await page.evaluate(() => window.__btn)) === 'ok');
  page = await open('none');

  // 6. Pegar una dirección parecida a la copiada (address poisoning / malware).
  await page.evaluate(() => { const s = getSelection(); const rg = document.createRange(); rg.selectNodeContents(document.getElementById('addr')); s.removeAllRanges(); s.addRange(rg); });
  await page.keyboard.press('Control+C');
  await page.waitForTimeout(150);
  await page.click('#poison'); // "malware" cambia el portapapeles por una dirección parecida
  await page.waitForTimeout(150);
  await page.click('#to');
  await page.keyboard.press('Control+V');
  await page.waitForTimeout(200);
  const val = await page.inputValue('#to');
  check('pegar una dirección parecida pero distinta: bloqueado con aviso', val === '' && (await overlays(page)) >= 1, `valor="${val}"`);
  // Pegar la dirección correcta funciona.
  await page.click('#copybtn');
  await page.waitForTimeout(150);
  await page.fill('#to', '');
  await page.click('#to');
  await page.keyboard.press('Control+V');
  await page.waitForTimeout(150);
  check('pegar la dirección correcta funciona', (await page.inputValue('#to')) === '0x52908400098527886E0F7030069857D2E4169EE7');

  // 7. Registro en el service worker e insignia.
  await page.waitForTimeout(300);
  const ev = await sw.evaluate(async () => ((await chrome.storage.local.get('events')).events ?? []).filter((e) => e.kind === 'fw-threat').map((e) => e.detail.split(' ')[0]));
  check('amenazas registradas en el service worker', ev.length >= 4, ev.join(', '));
} catch (e) {
  check('ejecución', false, e.stack);
} finally {
  await ctx.close();
  http.close();
}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} verificaciones OK`);
process.exit(failed ? 1 : 0);
