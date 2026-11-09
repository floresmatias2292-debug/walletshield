/**
 * Detección de homoglifos: caracteres de otros alfabetos (cirílico, griego,
 * latín extendido) o combinaciones ASCII que se ven igual que letras latinas.
 * Subconjunto curado de Unicode "confusables" (UTS #39) suficiente para
 * dominios; mantenerlo chico es intencional.
 */

const CONFUSABLES: Record<string, string> = {
  // Cirílico
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'һ': 'h', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k',
  'ӏ': 'l', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'г': 'r', 'ѕ': 's', 'т': 't',
  'и': 'u', 'ц': 'u', 'ѵ': 'v', 'ԝ': 'w', 'х': 'x', 'у': 'y', 'ү': 'y', 'з': '3', 'ԁ': 'd',
  'ɡ': 'g', 'ԍ': 'g', 'ь': 'b', 'п': 'n', 'с': 'c', 'ꙇ': 'i',
  // Griego
  'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
  'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'ϲ': 'c', 'ϳ': 'j', 'ς': 's',
  // Latín extendido / IPA sin descomposición NFD
  'ı': 'i', 'ȷ': 'j', 'ł': 'l', 'ƚ': 'l', 'ɩ': 'i', 'ø': 'o', 'ɵ': 'o', 'đ': 'd', 'ð': 'd',
  'ħ': 'h', 'ŧ': 't', 'ƀ': 'b', 'ß': 'ss', 'æ': 'ae', 'œ': 'oe', 'ɑ': 'a', 'ʋ': 'v', 'ʏ': 'y',
  'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j',
  'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't',
  'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ᴢ': 'z',
};

/** Sustituciones ASCII visualmente ambiguas en la barra de direcciones. */
const ASCII_LOOKALIKES: Array<[RegExp, string]> = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
  [/0/g, 'o'],
  [/1/g, 'l'],
  [/i/g, 'l'], // "i" y "l" se confunden en muchas tipografías de la barra
];

/**
 * "Esqueleto" visual de un texto: dos cadenas con el mismo esqueleto se ven
 * prácticamente iguales.
 */
export function skeleton(input: string): string {
  let out = '';
  for (const ch of input.normalize('NFKD')) {
    const code = ch.codePointAt(0) ?? 0;
    if (code >= 0x300 && code <= 0x36f) continue; // diacríticos combinantes
    out += CONFUSABLES[ch] ?? ch;
  }
  out = out.toLowerCase();
  for (const [re, rep] of ASCII_LOOKALIKES) out = out.replace(re, rep);
  return out;
}

export type ScriptName = 'latin' | 'cyrillic' | 'greek' | 'other';

function scriptOf(ch: string): ScriptName | null {
  if (/[a-z]/i.test(ch)) return 'latin';
  if (/\p{Script=Latin}/u.test(ch)) return 'latin';
  if (/\p{Script=Cyrillic}/u.test(ch)) return 'cyrillic';
  if (/\p{Script=Greek}/u.test(ch)) return 'greek';
  if (/[0-9_-]/.test(ch)) return null; // neutros
  return 'other';
}

/** Alfabetos presentes en una etiqueta (ignora dígitos y guiones). */
export function scriptsIn(label: string): Set<ScriptName> {
  const s = new Set<ScriptName>();
  for (const ch of label) {
    const sc = scriptOf(ch);
    if (sc) s.add(sc);
  }
  return s;
}

/** Mezcla latín con cirílico/griego en la misma etiqueta: típico de homógrafos. */
export function hasMixedScripts(label: string): boolean {
  const s = scriptsIn(label);
  return s.has('latin') && (s.has('cyrillic') || s.has('greek'));
}

/** Etiqueta 100 % cirílica/griega que se puede leer como palabra latina. */
export function isWholeScriptConfusable(label: string): boolean {
  const s = scriptsIn(label);
  if (s.has('latin') || s.size === 0) return false;
  if (!(s.has('cyrillic') || s.has('greek'))) return false;
  for (const ch of label) {
    if (/[0-9_-]/.test(ch)) continue;
    if (!(ch in CONFUSABLES)) return false;
  }
  return true;
}

/** true si el texto contiene algún carácter fuera de ASCII. */
export function hasNonAscii(s: string): boolean {
  return /[^\x00-\x7f]/.test(s);
}
