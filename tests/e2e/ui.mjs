// Test end-to-end de la fase 6: popup, página de opciones y su efecto real
// sobre la protección. Tenderly se simula con un HTTPS local.
import { createRequire } from 'node:module';
import { createServer as createHttp } from 'node:http';
import { createServer as createHttps } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const { chromium } = createRequire(import.meta.url)('playwright');
const SITE = resolve('tests/e2e/site');
const work = mkdtempSync(join(tmpdir(), 'ws-ui-'));

// Dapp de prueba (HTTP)
const http = createHttp((req, res) => {
  const u = new URL(req.url, 'http://x');
  const file = u.pathname === '/' ? 'dapp.html' : u.pathname.slice(1);
  try {
    const body = readFileSync(join(SITE, file), 'utf8').replace('MODE', 'assign');
    res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : 'text/html; charset=utf-8' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
// Tenderly simulado (HTTPS): registra lo que recibe.
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=api.tenderly.co', '-keyout', join(work, 'k.pem'), '-out', join(work, 'c.pem')], { stdio: 'ignore' });
const tenderlyHits = [];
const https = createHttps({ key: readFileSync(join(work, 'k.pem')), cert: readFileSync(join(work, 'c.pem')) }, (req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    if (req.headers.host?.startsWith('api.tenderly.co')) {
      tenderlyHits.push({ url: req.url, key: req.headers['x-access-key'], body: JSON.parse(body || '{}') });
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ status: true, logs: [{ name: 'Approval', inputs: [{ name: 'owner', value: '0x1111111111111111111111111111111111111111' }, { name: 'spender', value: '0xd4a1e2000000000000000000000000000000dead' }, { name: 'value', value: String((1n << 256n) - 1n) }], raw: { address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' } }] }));
    }
    res.writeHead(404); res.end();
  });
});
await new Promise((r) => http.listen(0, '127.0.0.1', r));
await new Promise((r) => https.listen(0, '127.0.0.1', r));

const ext = resolve('dist');
const ctx = await chromium.launchPersistentContext(join(work, 'p'), {
  channel: 'chromium',
  headless: true,
  acceptDownloads: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-proxy-server', '--ignore-certificate-errors',
    `--host-resolver-rules=MAP api.tenderly.co 127.0.0.1:${https.address().port}, MAP * 127.0.0.1:${http.address().port}`],
});

const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? '✔' : '✘'} ${name}${detail ? `  (${detail})` : ''}`); };
const pageErrors = [];
const modalOpen = (page) => page.evaluate(() => [...document.documentElement.children].some((e) => (e.getAttribute('style') ?? '').includes('inset: 0')));
async function waitModal(page, ms = 4000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await modalOpen(page)) return true; await page.waitForTimeout(50); } return false; }
const USER = '0x1111111111111111111111111111111111111111';
const MAX = 'f'.repeat(64);
const approveToPermit2 = { from: USER, to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', data: '0x095ea7b3' + '000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3' + MAX };
const approveToEoa = { from: USER, to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', data: '0x095ea7b3' + '000000000000000000000000d4a1e2000000000000000000000000000000dead' + MAX };

try {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
  const extId = sw.url().split('/')[2];
  const settings = () => sw.evaluate(async () => (await chrome.storage.local.get('settings')).settings);
  const openExt = async (path) => {
    const p = await ctx.newPage();
    p.on('pageerror', (e) => pageErrors.push(`${path}: ${e.message}`));
    await p.goto(`chrome-extension://${extId}/${path}`);
    return p;
  };

  // ── popup ───────────────────────────────────────────────────────────────
  const dapp = await ctx.newPage();
  await dapp.goto('http://uniswap-tools.example-dapp.com/');
  await dapp.waitForFunction(() => typeof window.__req === 'function');
  let pending = dapp.evaluate((tx) => window.__req('window', 'eth_sendTransaction', [tx]), approveToEoa);
  await waitModal(dapp);
  await dapp.keyboard.press('Enter');
  await pending;
  const tabId = await sw.evaluate(async () => (await chrome.tabs.query({ url: 'http://uniswap-tools.example-dapp.com/*' }))[0]?.id);

  const popup = await openExt(`popup/popup.html?tab=${tabId}`);
  await popup.waitForSelector('#host:not(:empty)');
  check('popup: muestra el sitio actual', (await popup.textContent('#host')) === 'uniswap-tools.example-dapp.com');
  check('popup: avisa que el dominio usa la marca Uniswap', /Uniswap|uniswap/i.test((await popup.textContent('#verdict')) ?? ''), await popup.textContent('#verdict'));
  await popup.waitForFunction(() => document.getElementById('today').textContent !== '0', null, { timeout: 3000 }).catch(() => undefined);
  check('popup: cuenta la amenaza bloqueada hoy', Number(await popup.textContent('#today')) >= 1, await popup.textContent('#today'));
  await popup.click('#trust');
  await popup.waitForFunction(() => /Sitio de confianza/.test(document.getElementById('verdict').textContent));
  const allowRule = await sw.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules({ ruleIds: [1] }))[0]?.condition.requestDomains);
  check('popup: "Confiar en este sitio" lo agrega y crea la regla DNR', (await settings()).allowlist.includes('uniswap-tools.example-dapp.com') && allowRule?.includes('uniswap-tools.example-dapp.com'));
  await popup.uncheck('#fw');
  await popup.waitForTimeout(200);
  check('popup: desactivar el firewall se refleja en el estado', (await settings()).firewall === false && (await popup.textContent('#status')) === 'Firewall desactivado');

  // Con el firewall apagado, el mismo drainer pasa (en una página nueva).
  const d2 = await ctx.newPage();
  await d2.goto('http://app.example-dapp.com/');
  await d2.waitForFunction(() => typeof window.__req === 'function');
  let r = await d2.evaluate((tx) => window.__req('window', 'eth_sendTransaction', [tx]), approveToEoa);
  check('con el firewall desactivado no se intercepta (respeta tu elección)', r.ok && !(await modalOpen(d2)));
  await popup.check('#fw');
  await popup.waitForTimeout(300);
  // La pestaña d2 ya estaba abierta (y guardó "firewall apagado"): debe enterarse del cambio.
  pending = d2.evaluate((tx) => window.__req('window', 'eth_sendTransaction', [tx]), approveToEoa);
  check('reactivar el firewall se aplica también a pestañas ya abiertas', await waitModal(d2));
  await d2.keyboard.press('Enter');
  await pending;

  // ── opciones ────────────────────────────────────────────────────────────
  const opt = await openExt('options/options.html');
  await opt.waitForSelector('#sources li');
  await opt.check('input[name=level][value=relaxed]');
  await opt.waitForTimeout(200);
  check('opciones: nivel "relajado" guardado', (await settings()).strictness === 'relaxed');
  const d3 = await ctx.newPage();
  await d3.goto('http://app.example-dapp.com/');
  await d3.waitForFunction(() => typeof window.__req === 'function');
  r = await d3.evaluate((tx) => window.__req('window', 'eth_sendTransaction', [tx]), approveToPermit2);
  check('modo relajado: aprobación ilimitada a Permit2 (riesgo medio) pasa sin modal', r.ok && !(await modalOpen(d3)));
  await opt.check('input[name=level][value=normal]');

  await opt.fill('#addHost', 'esto no es un dominio');
  await opt.click('#addForm button');
  check('opciones: rechaza un dominio inválido', /válido/.test((await opt.textContent('#addMsg')) ?? ''));
  await opt.fill('#addHost', 'https://app.uniswap.org/swap');
  await opt.click('#addForm button');
  await opt.waitForTimeout(200);
  check('opciones: acepta una URL y guarda solo el dominio', (await settings()).allowlist.includes('app.uniswap.org'));

  // Estado "ya sincronizado": una regla de ScamSniffer en su rango de IDs.
  await sw.evaluate(async () => chrome.declarativeNetRequest.updateDynamicRules({ addRules: [{ id: 30001, priority: 1, action: { type: 'block' }, condition: { requestDomains: ['e2e-ss.example'], resourceTypes: ['script'] } }] }));
  const ssBefore = await sw.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).filter((x) => x.id >= 30000 && x.id < 31024).length);
  await opt.locator('#sources li').nth(2).locator('input').uncheck();
  await opt.waitForTimeout(1500);
  const ssAfter = await sw.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).filter((x) => x.id >= 30000 && x.id < 31024).length);
  check('opciones: desactivar ScamSniffer quita sus reglas', (await settings()).sources.scamsniffer === false && ssBefore > 0 && ssAfter === 0, `${ssBefore} → ${ssAfter} reglas`);
  await opt.locator('#sources li').nth(2).locator('input').check();

  // Exportar e importar
  const [download] = await Promise.all([opt.waitForEvent('download'), opt.click('#export')]);
  const exported = readFileSync(await download.path(), 'utf8');
  const parsed = JSON.parse(exported);
  check('exportar: archivo válido con los sitios de confianza y sin secretos', parsed.app === 'WalletShield' && parsed.settings.allowlist.includes('app.uniswap.org') && !/access|apikey|secret/i.test(exported));
  const imp = join(work, 'import.json');
  writeFileSync(imp, JSON.stringify({ ...parsed, settings: { ...parsed.settings, strictness: 'strict', allowlist: ['jup.ag', '<script>'], simulation: { enabled: true, account: 'x', project: 'y' } } }));
  await opt.setInputFiles('#import', imp);
  await opt.waitForTimeout(300);
  const afterImport = await settings();
  check('importar: aplica la configuración y descarta lo inválido', afterImport.strictness === 'strict' && JSON.stringify(afterImport.allowlist) === '["jup.ag"]');
  check('importar: nunca activa la simulación (requiere una key local)', afterImport.simulation.enabled === false);
  await opt.check('input[name=level][value=normal]');

  // Simulación con Tenderly
  await opt.fill('#simAccount', 'mi-cuenta');
  await opt.fill('#simProject', 'mi-proyecto');
  await opt.fill('#simKey', 'tk_prueba_123');
  await opt.check('#simEnabled');
  await opt.click('#simSave');
  await opt.waitForTimeout(300);
  const keyInSettings = JSON.stringify(await settings()).includes('tk_prueba_123');
  check('simulación: activada y la key NO queda en los ajustes', (await settings()).simulation.enabled === true && !keyInSettings, await opt.textContent('#simMsg'));
  const d4 = await ctx.newPage();
  await d4.goto('http://app.example-dapp.com/');
  await d4.waitForFunction(() => typeof window.__req === 'function');
  pending = d4.evaluate((tx) => window.__req('window', 'eth_sendTransaction', [tx]), approveToEoa);
  await waitModal(d4, 8000);
  await d4.screenshot({ path: 'docs/modal-simulacion.png' }).catch(() => undefined);
  await d4.keyboard.press('Enter');
  await pending;
  const hit = tenderlyHits[0];
  check('simulación: consulta Tenderly v2 con tu key y la transacción', !!hit && hit.url === '/api/v2/account/mi-cuenta/project/mi-proyecto/simulations/simulate' && hit.key === 'tk_prueba_123' && hit.body.call_args?.to?.toLowerCase() === approveToEoa.to.toLowerCase(), hit ? hit.url : 'sin llamadas');
  await opt.click('#simClear');
  await opt.waitForTimeout(200);
  const hasKey = await sw.evaluate(async () => Object.keys(await chrome.storage.local.get(null)).some((k) => k.startsWith('secret:')));
  check('simulación: "Borrar API key" la elimina y desactiva la simulación', !hasKey && (await settings()).simulation.enabled === false);

  // Registro de eventos
  await opt.reload();
  await opt.waitForSelector('#log tr');
  const rows = await opt.locator('#log tr').count();
  check('registro: muestra los eventos', rows >= 2, `${rows} filas`);
  await opt.selectOption('#filter', 'block');
  const blockRows = await opt.locator('#log tr').allTextContents();
  check('registro: filtro de bloqueos', blockRows.length >= 1 && blockRows.every((t) => /bloquead/i.test(t)));
  await opt.click('#clearLog');
  await opt.waitForTimeout(200);
  check('registro: borrar lo vacía', /Sin eventos/.test((await opt.textContent('#log')) ?? ''));

  // Seguridad
  check('popup y opciones sin errores de JavaScript', pageErrors.length === 0, pageErrors.join(' | '));
  await popup.setViewportSize({ width: 360, height: 640 });
  await popup.reload();
  await popup.waitForSelector('#host:not(:empty)');
  await popup.screenshot({ path: 'docs/popup.png', fullPage: true });
  await opt.setViewportSize({ width: 900, height: 1400 });
  await opt.screenshot({ path: 'docs/opciones.png', fullPage: true });
} catch (e) {
  check('ejecución', false, e.stack);
} finally {
  await ctx.close();
  http.close();
  https.close();
}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} verificaciones OK`);
process.exit(failed ? 1 : 0);
