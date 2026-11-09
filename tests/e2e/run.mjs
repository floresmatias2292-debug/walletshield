// Test end-to-end: carga dist/ en Chromium real y verifica el bloqueo DNR,
// el diff incremental de listas, las heurísticas y el flujo "continuar".
// Las listas se sirven desde un HTTPS local que imita raw.githubusercontent.com.
import { createRequire } from 'node:module';
import { createServer as createHttp } from 'node:http';
import { createServer as createHttps } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Playwright se resuelve con require (instalación global o local: npm i -D playwright).
const { chromium } = createRequire(import.meta.url)('playwright');

const LISTS_DIR = process.env.WS_LISTS_DIR; // carpeta con mm.json y pd.json reales
if (!LISTS_DIR || !existsSync(join(LISTS_DIR, 'mm.json'))) {
  console.error('Definí WS_LISTS_DIR con mm.json y pd.json (ver README)');
  process.exit(2);
}

// --- fixtures de listas -----------------------------------------------------
function fnv1a(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; }
const mm = JSON.parse(readFileSync(join(LISTS_DIR, 'mm.json'), 'utf8'));
const REMOVED = 'swiftsales24.com'; // dominio de la lista que las heurísticas no detectan
const removedBucket = fnv1a(REMOVED) % 128;
const SIBLING = mm.blacklist.find((d) => d !== REMOVED && /^[a-z0-9.-]+$/.test(d) && !d.includes('/') && fnv1a(d) % 128 === removedBucket);
mm.blacklist = mm.blacklist.filter((d) => d !== REMOVED);
mm.blacklist.push('e2e-mm-added-domain.xyz');
const ss = ['e2e-scamsniffer-domain.xyz', 'sites.google.com', 'r2.dev', 'app.uniswap.org'];
for (let i = 0; i < 5000; i++) ss.push(`e2e-bulk-${i}.example-phish.xyz`);
// WS_SS_REAL=1: usa además la lista real completa de ScamSniffer (prueba de escala).
const SS_REAL = process.env.WS_SS_REAL === '1' && existsSync(join(LISTS_DIR, 'ss_domains.json'));
if (SS_REAL) for (const d of JSON.parse(readFileSync(join(LISTS_DIR, 'ss_domains.json'), 'utf8'))) ss.push(d);
const listFiles = {
  '/MetaMask/eth-phishing-detect/main/src/config.json': JSON.stringify(mm),
  '/polkadot-js/phishing/master/all.json': readFileSync(join(LISTS_DIR, 'pd.json'), 'utf8'),
  '/scamsniffer/scam-database/main/blacklist/domains.json': JSON.stringify(ss),
};

// --- servidores --------------------------------------------------------------
const work = mkdtempSync(join(tmpdir(), 'ws-e2e-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=raw.githubusercontent.com',
  '-keyout', join(work, 'k.pem'), '-out', join(work, 'c.pem')], { stdio: 'ignore' });
const listHits = [];
const https = createHttps({ key: readFileSync(join(work, 'k.pem')), cert: readFileSync(join(work, 'c.pem')) }, (req, res) => {
  listHits.push(req.url);
  const body = listFiles[req.url];
  if (!body) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'content-type': 'application/json', etag: `"${req.url.length}-${body.length}"` });
  res.end(body);
});
const pageHits = [];
const http = createHttp((req, res) => {
  pageHits.push(`${req.headers.host}${req.url}`);
  if (req.url === '/drainer.js') { res.writeHead(200, { 'content-type': 'text/javascript' }); return res.end('window.__drainerLoaded = true;'); }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  const extra = req.headers.host.startsWith('compromised-legit') ? '<script src="http://e2e-scamsniffer-domain.xyz/drainer.js"></script>' : '';
  res.end(`<!doctype html><title>ok</title><h1 id="ok">${req.headers.host}</h1>${extra}`);
});
await new Promise((r) => https.listen(0, '127.0.0.1', r));
await new Promise((r) => http.listen(0, '127.0.0.1', r));
const HTTPS_PORT = https.address().port;
const HTTP_PORT = http.address().port;

// --- navegador ----------------------------------------------------------------
const ext = resolve('dist');
const ctx = await chromium.launchPersistentContext(join(work, 'profile'), {
  channel: 'chromium',
  headless: true,
  args: [
    `--disable-extensions-except=${ext}`,
    `--load-extension=${ext}`,
    '--no-proxy-server',
    '--ignore-certificate-errors',
    `--host-resolver-rules=MAP raw.githubusercontent.com 127.0.0.1:${HTTPS_PORT}, MAP * 127.0.0.1:${HTTP_PORT}`,
  ],
});

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`${ok ? '✔' : '✘'} ${name}${detail ? `  (${detail})` : ''}`);
}

try {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
  const extId = sw.url().split('/')[2];

  // Esperar a que termine la sincronización inicial de las tres fuentes.
  const t0 = Date.now();
  let states;
  for (;;) {
    states = await sw.evaluate(async () => chrome.storage.local.get(['source:metamask', 'source:polkadot', 'source:scamsniffer']));
    if (Object.keys(states).length === 3 && Object.values(states).every((s) => s.lastSync || s.error)) break;
    if (Date.now() - t0 > 180000) throw new Error('timeout de sincronización ' + JSON.stringify(states));
    await new Promise((r) => setTimeout(r, 250));
  }
  const syncMs = Date.now() - t0;
  const errs = Object.entries(states).filter(([, s]) => s.error).map(([k, s]) => `${k}: ${s.error}`);
  check('sincronización inicial sin errores', errs.length === 0, errs.join('; ') || `${syncMs} ms`);

  const dnr = await sw.evaluate(async () => ({
    dynamic: (await chrome.declarativeNetRequest.getDynamicRules()).length,
    rulesets: await chrome.declarativeNetRequest.getEnabledRulesets(),
    disabledMM: await chrome.declarativeNetRequest.getDisabledRuleIds({ rulesetId: 'static_metamask' }),
    ssDomains: (await chrome.declarativeNetRequest.getDynamicRules()).filter((r) => r.id >= 30000 && r.id < 31024 && r.id % 2 === 1).reduce((n, r) => n + r.condition.requestDomains.length, 0),
  }));
  check('rulesets estáticos activos', dnr.rulesets.includes('static_metamask') && dnr.rulesets.includes('static_polkadot'), dnr.rulesets.join(','));
  check('baja en MetaMask deshabilita SOLO su bucket estático', dnr.disabledMM.length === 2, `deshabilitadas: ${dnr.disabledMM.join(',')}`);
  check('ScamSniffer cargado como reglas dinámicas (sin entradas peligrosas)', SS_REAL ? dnr.ssDomains > 300000 : dnr.ssDomains === 5001, `${dnr.ssDomains} dominios, ${dnr.dynamic} reglas dinámicas`);

  const page = await ctx.newPage();
  async function visit(url) {
    try { await page.goto(url, { waitUntil: 'load', timeout: 10000 }); } catch (e) { /* redirecciones abortan goto */ }
    await page.waitForTimeout(400);
    return page.url();
  }
  const isBlocked = (u) => u.startsWith('chrome-extension://') && u.includes('/blocked/blocked.html');

  let u = await visit(`http://${SIBLING}/`);
  check(`dominio del snapshot bloqueado (${SIBLING})`, isBlocked(u), u);
  const shownHost = isBlocked(u) ? await page.locator('#host').textContent() : '';
  check('la página de bloqueo muestra el dominio', shownHost === SIBLING, shownHost ?? '');

  u = await visit(`http://${REMOVED}/`);
  check('dominio quitado de la lista ya NO se bloquea (diff aplicado)', !isBlocked(u), u);

  u = await visit('http://e2e-mm-added-domain.xyz/');
  check('alta nueva de MetaMask bloqueada (regla dinámica)', isBlocked(u), u);

  u = await visit('http://e2e-scamsniffer-domain.xyz/');
  check('dominio de ScamSniffer bloqueado', isBlocked(u), u);
  u = await visit('http://e2e-bulk-4321.example-phish.xyz/');
  check('subdominio/entrada masiva de ScamSniffer bloqueada', isBlocked(u), u);

  u = await visit('http://compromised-legit.example/');
  const drainer = await page.evaluate(() => window.__drainerLoaded === true).catch(() => null);
  check('script de drainer desde dominio listado bloqueado en sitio legítimo', !isBlocked(u) && drainer === false, `drainerLoaded=${drainer}`);

  u = await visit('http://sites.google.com/view/metamask-microsoft/home');
  check('página de phishing en Google Sites bloqueada por ruta', isBlocked(u), u);
  u = await visit('http://sites.google.com/view/mi-sitio-legitimo/home');
  check('otras páginas de Google Sites NO se bloquean', !isBlocked(u), u);
  u = await visit('http://r2.dev/');
  check('entrada peligrosa "r2.dev" descartada', !isBlocked(u), u);

  for (const legit of ['app.uniswap.org', 'opensea.io', 'jup.ag', 'raydium.io', 'www.google.com']) {
    u = await visit(`http://${legit}/`);
    check(`sin falso positivo: ${legit}`, !isBlocked(u), u);
  }

  u = await visit('http://uniswap-claim-e2e.com/');
  check('heurística: "uniswap-claim-e2e.com" bloqueado', isBlocked(u) && u.includes('src=h'), u);
  if (isBlocked(u)) {
    const title = await page.locator('#title').textContent();
    check('mensaje en español de imitación', /imitación/.test(title ?? ''), title ?? '');
  }
  u = await visit('http://xn--uniswp-7nf.org/');
  check('heurística: homógrafo uniswаp.org (cirílica) bloqueado', isBlocked(u), u);

  // Flujo "Continuar de todos modos": exige checkbox y solo dura la sesión.
  u = await visit('http://e2e-mm-added-domain.xyz/');
  await page.locator('details summary').click();
  const disabledBefore = await page.locator('#proceed').isDisabled();
  await page.locator('#ack').check();
  await page.locator('#proceed').click();
  await page.waitForURL('http://e2e-mm-added-domain.xyz/', { timeout: 5000 }).catch(() => undefined);
  check('"Continuar" exige confirmar y luego abre el sitio', disabledBefore && page.url() === 'http://e2e-mm-added-domain.xyz/', page.url());

  // La página de bloqueo dentro de un iframe no debe hacer nada (anti-clickjacking).
  await visit('http://attacker.example/');
  const framed = await page.evaluate(async (id) => {
    const f = document.createElement('iframe');
    f.src = `chrome-extension://${id}/blocked/blocked.html`;
    document.body.append(f);
    await new Promise((r) => setTimeout(r, 800));
    try { return f.contentDocument ? 'accesible' : 'aislado'; } catch { return 'aislado'; }
  }, extId);
  check('blocked.html no es accesible ni enmarcable por un sitio', framed === 'aislado', framed);

  console.log(`\nSincronización inicial: ${syncMs} ms · descargas de listas: ${listHits.length}`);
} catch (e) {
  check('ejecución', false, e.message);
} finally {
  await ctx.close();
  https.close();
  http.close();
}
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} verificaciones OK`);
process.exit(failed.length ? 1 : 0);
