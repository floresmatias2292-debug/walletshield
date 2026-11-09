// Phantom simulado: API legacy (window.phantom.solana / window.solana), Wallet
// Standard y provider EVM (window.phantom.ethereum). Registra lo que recibe.
(() => {
  const calls = (window.__solCalls = []);
  const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
  const bytesOf = (tx) => (tx instanceof Uint8Array ? tx : tx.serializeMessage());
  const solana = {
    isPhantom: true,
    publicKey: { toBase58: () => 'Mock' },
    connect: async () => ({ publicKey: 'Mock' }),
    signTransaction: async (tx) => { calls.push('signTransaction:' + hex(bytesOf(tx)).slice(0, 16)); return tx; },
    signAllTransactions: async (txs) => { calls.push('signAllTransactions'); return txs; },
    signAndSendTransaction: async (tx) => { calls.push('signAndSendTransaction'); return { signature: 'sig' }; },
    signMessage: async (m) => { calls.push('signMessage'); return { signature: new Uint8Array(64) }; },
    request: async ({ method }) => { calls.push('request:' + method); return { signature: 'sig' }; },
  };
  const ethereum = { isPhantom: true, request: async ({ method }) => { calls.push('eth:' + method); return '0x1'; }, on() { return this; } };
  window.__rawSolana = solana;
  window.phantom = { solana, ethereum };
  window.solana = solana;

  const wallet = {
    version: '1.0.0', name: 'MockPhantom', icon: 'data:image/svg+xml,<svg/>', chains: ['solana:mainnet'], accounts: [],
    features: {
      'standard:connect': { version: '1.0.0', connect: async () => ({ accounts: [] }) },
      'solana:signTransaction': {
        version: '1.0.0', supportedTransactionVersions: ['legacy', 0],
        signTransaction: async (...inputs) => { for (const i of inputs) calls.push('std:signTransaction:' + hex(i.transaction).slice(0, 16)); return inputs.map((i) => ({ signedTransaction: i.transaction })); },
      },
      'solana:signMessage': { version: '1.0.0', signMessage: async (...inputs) => { calls.push('std:signMessage'); return inputs.map(() => ({ signedMessage: new Uint8Array(1), signature: new Uint8Array(64) })); } },
    },
  };
  const callback = ({ register }) => register(wallet);
  window.dispatchEvent(new CustomEvent('wallet-standard:register-wallet', { detail: callback }));
  window.addEventListener('wallet-standard:app-ready', ({ detail }) => callback(detail));
})();
