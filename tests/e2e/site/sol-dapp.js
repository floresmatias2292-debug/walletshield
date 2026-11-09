// "Dapp" de Solana de prueba (lado app de Wallet Standard + helpers).
const stdWallets = [];
const api = { register: (...w) => { stdWallets.push(...w); return () => {}; } };
window.addEventListener('wallet-standard:register-wallet', ({ detail }) => detail(api));
window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: api }));
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const run = (p) => p.then(() => ({ ok: true }), (e) => ({ ok: false, message: e && e.message }));
window.__legacyTx = (b, via) => run((via === 'solana' ? window.solana : window.phantom.solana).signTransaction({ serializeMessage: () => b64(b) }));
window.__legacyMsg = (b) => run(window.phantom.solana.signMessage(b64(b)));
window.__request = (method, message) => run(window.phantom.solana.request({ method, params: { message } }));
window.__stdTx = (b, mutate) => {
  const bytes = b64(b);
  const p = stdWallets[0].features['solana:signTransaction'].signTransaction({ account: null, transaction: bytes, chain: 'solana:mainnet' });
  if (mutate) setTimeout(() => bytes.fill(0xee, 10, 40), 0); // la página intenta cambiar los bytes después
  return run(p);
};
window.__stdMsg = (text) => run(stdWallets[0].features['solana:signMessage'].signMessage({ account: null, message: new TextEncoder().encode(text) }));
// Objeto "tramposo": devuelve una transacción inocente la primera vez y otra después.
window.__toctou = (good, bad) => { let n = 0; return run(window.phantom.solana.signTransaction({ serializeMessage: () => b64(n++ === 0 ? good : bad) })); };
window.__phantomEth = () => run(window.phantom.ethereum.request({ method: 'eth_sign', params: ['0x1111111111111111111111111111111111111111', '0x' + 'ab'.repeat(32)] }));
window.__stdCount = () => stdWallets.length;
window.__bench = async (b, n) => {
  const tx = { serializeMessage: () => b64(b) };
  let t0 = performance.now(); for (let i = 0; i < n; i++) await window.__rawSolana.signTransaction(tx);
  const raw = (performance.now() - t0) / n;
  t0 = performance.now(); for (let i = 0; i < n; i++) await window.phantom.solana.signTransaction(tx);
  return { rawMs: raw, proxyMs: (performance.now() - t0) / n };
};
