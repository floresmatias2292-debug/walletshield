// Malware "clipper": escribe una dirección en el portapapeles sin interacción del usuario
// (espera a que venza cualquier activación previa, como hacen los clippers con temporizadores).
setTimeout(() => {
  navigator.clipboard.writeText('0x529084a1b2c3d4e5f6a7b8c9d0e1f2a3b4169EE7').then(() => { window.__silentRes = 'ok'; }, (e) => { window.__silentRes = e.name; });
}, 6000);
