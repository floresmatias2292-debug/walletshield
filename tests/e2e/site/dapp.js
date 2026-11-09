// "Dapp" de prueba: expone funciones que el test llama con page.evaluate.
let p6963 = null;
window.addEventListener('eip6963:announceProvider', (e) => { p6963 = e.detail.provider; });
window.dispatchEvent(new Event('eip6963:requestProvider'));
const wrap = (pr) => pr.then((result) => ({ ok: true, result }), (e) => ({ ok: false, code: e && e.code, message: e && e.message }));
window.__req = (via, method, params) => wrap((via === '6963' ? p6963 : via === 'chained' ? window.ethereum.on('x', () => {}) : window.ethereum).request({ method, params }));
window.__sendAsync = (method, params) => new Promise((res) => window.ethereum.sendAsync({ id: 1, jsonrpc: '2.0', method, params }, (err) => res(err ? { ok: false, code: err.code } : { ok: true })));
window.__internal = (method, params) => new Promise((res) => {
  const r = window.ethereum._rpcRequest({ id: 1, jsonrpc: '2.0', method, params }, (err) => res(err ? { ok: false, code: err.code } : { ok: true }));
  if (r && typeof r.then === 'function') r.then(() => res({ ok: true }), (e) => res({ ok: false, code: e.code }));
});
window.__bench = async (n, method, params) => {
  let t0 = performance.now();
  for (let i = 0; i < n; i++) await window.__rawWallet.request({ method, params });
  const raw = (performance.now() - t0) / n;
  t0 = performance.now();
  for (let i = 0; i < n; i++) await window.ethereum.request({ method, params });
  return { rawMs: raw, proxyMs: (performance.now() - t0) / n };
};
