/**
 * Firmas de scripts de drainers.
 *
 * No existe (que hayamos podido verificar) una lista pública, mantenida y con
 * licencia abierta de hashes de kits de drainers. Por eso el motor admite dos
 * tipos de reglas:
 *  - `sha256`: hash exacto del código de un kit conocido (lista ampliable);
 *  - `all`/`any`: indicadores de comportamiento que los kits comparten y que
 *    un sitio legítimo casi nunca combina.
 * Las reglas son DATOS: nunca se ejecuta código descargado.
 */
import type { RiskLevel } from '../risk';

export interface ScriptRule {
  readonly id: string;
  readonly risk: RiskLevel;
  readonly text: string;
  /** Todos estos patrones deben aparecer. */
  readonly all?: readonly RegExp[];
  /** Además, al menos `min` de estos (por defecto 1). */
  readonly any?: readonly RegExp[];
  readonly min?: number;
  /** Hashes SHA-256 (hex) de scripts completos. */
  readonly sha256?: readonly string[];
}

const WALLET_SIGN = /eth_signTypedData_v4|setApprovalForAll|PermitBatch|increaseAllowance|signAllTransactions|eth_sendTransaction/;

export const SCRIPT_RULES: readonly ScriptRule[] = [
  {
    id: 'telegram-exfil',
    risk: 'high',
    text: 'El código de la página envía datos a un bot de Telegram y además pide firmas a la wallet: es como los kits de drainers reportan a sus operadores.',
    all: [/api\.telegram\.org\/bot/i, WALLET_SIGN],
  },
  {
    id: 'asset-scan-and-drain',
    risk: 'high',
    text: 'El código recorre tus activos (tokens y NFTs) en APIs de terceros y prepara permisos sobre ellos: patrón de kits de drainers.',
    all: [WALLET_SIGN, /setApprovalForAll|PermitBatch|PermitTransferFrom/],
    any: [/ankr_getAccountBalance/, /deep-index\.moralis\.io/, /api\.covalenthq\.com/, /\/api\/v2\/chain\/[a-z]+\/account\/[^/]+\/nfts/, /getTokenBalances|alchemy_getTokenBalances/],
    min: 1,
  },
  {
    id: 'drainer-vocabulary',
    risk: 'high',
    text: 'El código contiene términos de configuración propios de kits de drainers.',
    any: [/\bdrainer\b/i, /seaport_?drain/i, /permit2?_?drain/i, /\bminValueToDrain\b/i, /\bDRAIN_(NFT|TOKEN|NATIVE)/i, /\bdrainAll\b/],
    min: 2,
  },
  {
    id: 'provider-hook',
    risk: 'medium',
    text: 'El código reemplaza funciones del provider de la wallet (window.ethereum.request).',
    any: [/ethereum\.request\s*=(?!=)/, /ethereum\.send(Async)?\s*=(?!=)/],
  },
  {
    id: 'clipboard-swap',
    risk: 'high',
    text: 'El código reemplaza direcciones cripto en el portapapeles.',
    all: [/addEventListener\(\s*['"]copy['"]/, /clipboardData\.setData|navigator\.clipboard\.writeText/, /0x\[a-fA-F0-9\]\{40\}|\[13\]\[a-km-zA-HJ-NP-Z1-9\]|bc1/],
  },
  {
    id: 'known-kit-hash',
    risk: 'high',
    text: 'El script coincide con el hash de un kit de drainer conocido.',
    // Lista inicialmente vacía: se completa con hashes verificados (ver README).
    sha256: [],
  },
];

export interface ScriptHit {
  readonly id: string;
  readonly risk: RiskLevel;
  readonly text: string;
}

export function matchRules(code: string, sha256: string | null, rules: readonly ScriptRule[] = SCRIPT_RULES): ScriptHit[] {
  const hits: ScriptHit[] = [];
  for (const r of rules) {
    if (r.sha256) {
      if (sha256 && r.sha256.includes(sha256)) hits.push({ id: r.id, risk: r.risk, text: r.text });
      continue;
    }
    if (r.all && !r.all.every((re) => re.test(code))) continue;
    if (r.any) {
      const n = r.any.filter((re) => re.test(code)).length;
      if (n < (r.min ?? 1)) continue;
    }
    if (!r.all && !r.any) continue;
    hits.push({ id: r.id, risk: r.risk, text: r.text });
  }
  return hits;
}
