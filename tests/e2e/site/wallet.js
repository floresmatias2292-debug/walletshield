// Wallet simulada (como el "inpage" de MetaMask/Rabby). Responde al instante
// y registra qué métodos le llegaron, para saber si una firma fue bloqueada.
(() => {
  const mode = new URL(document.currentScript.src).searchParams.get('mode') || 'assign';
  const calls = (window.__walletCalls = []);
  const USER = '0x1111111111111111111111111111111111111111';
  const code = { '0xd4a1e2000000000000000000000000000000dead': '0x', '0xc0ffee0000000000000000000000000000c0ffee': '0x6080604052' };
  function handle({ method, params }) {
    calls.push(method);
    switch (method) {
      case 'eth_chainId': return '0x1';
      case 'eth_accounts': case 'eth_requestAccounts': return [USER];
      case 'eth_getCode': return code[String(params[0]).toLowerCase()] ?? '0x';
      case 'eth_getBalance': return '0xde0b6b3a7640000';
      case 'eth_call': return '0x' + '0'.repeat(63) + '6';
      default: return '0x' + 'ab'.repeat(65);
    }
  }
  const provider = {
    isMetaMask: true,
    request: async (args) => handle(args),
    sendAsync(p, cb) { cb(null, { id: p.id, jsonrpc: '2.0', result: handle(p) }); },
    _rpcRequest(p, cb) { cb(null, { result: handle(p) }); },
    on() { return this; },
    removeListener() { return this; },
  };
  window.__rawWallet = provider; // solo para medir la latencia sin proxy
  if (mode === 'define') Object.defineProperty(window, 'ethereum', { value: provider, configurable: false, writable: false });
  else window.ethereum = provider;
  const announce = () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
    detail: Object.freeze({ info: { uuid: '1', name: 'Mock', icon: 'data:,', rdns: 'io.mock' }, provider }),
  }));
  window.addEventListener('eip6963:requestProvider', announce);
  announce();
})();
