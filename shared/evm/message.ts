/** personal_sign y eth_sign. */
import type { AnalysisContext } from './context';
import { bytesToText, hexToBytes, isAddress, isHex } from './hex';
import type { Report } from './tx';

/** Primera línea de un mensaje Sign-In with Ethereum (EIP-4361). */
const SIWE_RE = /^(?:(?<scheme>[a-z][a-z0-9+.-]*):\/\/)?(?<domain>[^\s/]+) wants you to sign in with your Ethereum account:\n/;

export function siweDomain(text: string): string | null {
  const m = SIWE_RE.exec(text);
  return m?.groups?.domain ?? null;
}

function hostOnly(d: string): string {
  return d.replace(/:\d+$/, '').toLowerCase();
}

/** Mensaje de personal_sign: params = [mensaje, dirección] (algunas dapps invierten el orden). */
export function personalSignMessage(params: readonly unknown[]): string | null {
  const [a, b] = params;
  if (typeof a === 'string' && !(isAddress(a) && typeof b === 'string' && !isAddress(b))) return a;
  return typeof b === 'string' ? b : null;
}

export function analyzePersonalSign(ctx: AnalysisContext, r: Report, raw: string): void {
  let text: string | null = raw;
  let bytes: Uint8Array | null = null;
  if (isHex(raw)) {
    bytes = hexToBytes(raw);
    text = bytes ? bytesToText(bytes) : null;
  }
  if (bytes && bytes.length === 32 && (text === null || !/^[\x20-\x7e\s]{32}$/.test(text))) {
    r.setTitle('Firma ciega de un hash');
    r.add({
      code: 'blind-hash',
      risk: 'high',
      text: 'Te piden firmar 32 bytes ilegibles (un hash). Puede ser la firma de una transacción o un permiso que no puedes ver. Ninguna dapp legítima necesita esto.',
    });
    return;
  }
  if (text === null) {
    r.setTitle('Firma de datos binarios');
    r.add({ code: 'binary-message', risk: 'medium', text: 'El mensaje no es texto legible: no se puede saber qué firmas.' });
    return;
  }
  const domain = siweDomain(text);
  if (domain) {
    r.setTitle('Iniciar sesión con Ethereum');
    r.line(`Inicio de sesión en "${domain.slice(0, 80)}".`);
    if (hostOnly(domain) !== ctx.input.pageHost.toLowerCase()) {
      r.add({
        code: 'siwe-mismatch',
        risk: 'high',
        text: `El mensaje es para iniciar sesión en "${domain.slice(0, 80)}", pero estás en "${ctx.input.pageHost}". Un sitio falso podría estar robando tu sesión.`,
      });
    } else {
      r.add({ code: 'siwe', risk: 'none', text: 'Inicio de sesión para este mismo sitio.' });
    }
    return;
  }
  r.setTitle('Firma de un mensaje de texto');
  r.line(`"${text.length > 280 ? `${text.slice(0, 280)}…` : text}"`);
  r.add({ code: 'text-message', risk: 'low', text: 'Firmar texto no mueve fondos por sí solo. Lee el mensaje antes de firmar.' });
}

export function analyzeEthSign(r: Report): void {
  r.setTitle('Firma ciega (eth_sign)');
  r.add({
    code: 'eth-sign',
    risk: 'high',
    text: 'eth_sign firma datos arbitrarios sin mostrar qué son: con una firma así pueden robar todos tus fondos. Ninguna dapp legítima actual la necesita. Se bloquea por defecto.',
  });
}
