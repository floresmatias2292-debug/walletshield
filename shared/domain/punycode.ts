/**
 * Decodificador Punycode (RFC 3492) mínimo, solo para mostrar y analizar
 * etiquetas IDN ("xn--..."). No hace falta codificar: Chrome ya entrega los
 * hostnames en ASCII.
 */
const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_LABEL = 63;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function digitValue(cp: number): number {
  if (cp >= 0x30 && cp <= 0x39) return cp - 22; // 0-9 → 26-35
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41; // A-Z
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61; // a-z
  return BASE;
}

/** Decodifica una etiqueta sin el prefijo "xn--". Devuelve null si es inválida. */
export function decodePunycodeLabel(input: string): string | null {
  if (input.length > MAX_LABEL) return null;
  const output: number[] = [];
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  const basic = input.lastIndexOf('-');
  for (let j = 0; j < Math.max(basic, 0); j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return null;
    output.push(c);
  }
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) return null;
      const digit = digitValue(input.charCodeAt(idx++));
      if (digit >= BASE) return null;
      i += digit * w;
      if (i > 0x10ffff * 64) return null;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff) return null;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Convierte un hostname ASCII a Unicode (para mostrar y para detectar homoglifos). */
export function hostToUnicode(host: string): string {
  return host
    .split('.')
    .map((label) => {
      if (!label.startsWith('xn--')) return label;
      return decodePunycodeLabel(label.slice(4)) ?? label;
    })
    .join('.');
}
