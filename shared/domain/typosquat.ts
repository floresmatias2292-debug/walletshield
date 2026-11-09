import type { RiskLevel } from '../risk';
import { maxRisk } from '../risk';
import { hasMixedScripts, hasNonAscii, isWholeScriptConfusable, skeleton } from './homoglyph';
import { boundedDistance } from './levenshtein';
import { LEGIT_DOMAINS, type LegitDomain } from './legit-domains';
import { isSameOrSubdomain, mainLabel, publicSuffix, registrableDomain, stripCommonPrefix } from './normalize';
import { hostToUnicode } from './punycode';

export type DomainReasonCode =
  | 'homoglyph' // se ve idéntico a un dominio legítimo
  | 'mixed-script' // mezcla alfabetos en una etiqueta
  | 'punycode' // dominio internacionalizado (IDN)
  | 'typosquat' // a 1-2 letras de un dominio legítimo
  | 'tld-swap' // misma marca, otra extensión
  | 'brand-combo' // marca + palabras como "claim", "airdrop"
  | 'brand-in-subdomain' // marca usada como subdominio de otro sitio
  | 'new-domain'; // registrado hace menos de 30 días (RDAP, opcional)

export interface DomainReason {
  readonly code: DomainReasonCode;
  readonly risk: RiskLevel;
  /** Dominio legítimo imitado, si aplica. */
  readonly target?: string;
}

export interface DomainVerdict {
  readonly host: string;
  readonly unicodeHost: string;
  readonly risk: RiskLevel;
  readonly reasons: readonly DomainReason[];
  /** true si el host es (o es subdominio de) un dominio legítimo conocido. */
  readonly legit: boolean;
}

/** Palabras típicas de páginas de drainers. */
const LURE_WORDS = new Set([
  'claim', 'claims', 'airdrop', 'airdrops', 'reward', 'rewards', 'bonus', 'giveaway', 'free', 'mint',
  'migrate', 'migration', 'sync', 'resync', 'restore', 'recover', 'recovery', 'validate', 'validation',
  'verify', 'verification', 'rectify', 'fix', 'unlock', 'unstake', 'refund', 'compensation',
  'support', 'helpdesk', 'secure', 'security', 'login', 'connect', 'dapp', 'wallet', 'web3',
  'drop', 'event', 'gift', 'snapshot', 'eligibility', 'eligible', 'checker', 'portal', 'official',
]);

interface IndexedLegit {
  readonly domain: string;
  readonly registrable: string;
  readonly label: string;
  readonly generic: boolean;
  readonly skeletonDomain: string;
  readonly skeletonLabel: string;
}

function indexLegit(list: readonly LegitDomain[]): IndexedLegit[] {
  return list.map((l) => {
    const registrable = registrableDomain(l.domain);
    const label = mainLabel(l.domain);
    return {
      domain: l.domain,
      registrable,
      label,
      generic: l.generic === true,
      skeletonDomain: skeleton(registrable),
      skeletonLabel: skeleton(label),
    };
  });
}

/** Tolerancia de typosquatting según largo: etiquetas cortas no se comparan. */
function tolerance(len: number): number {
  if (len < 5) return 0;
  if (len < 9) return 1;
  return 2;
}

export class DomainAnalyzer {
  private readonly legit: IndexedLegit[];
  /** esqueleto de etiqueta distintiva → dominio legítimo */
  private readonly brandSkeletons: Map<string, string>;

  constructor(list: readonly LegitDomain[] = LEGIT_DOMAINS) {
    this.legit = indexLegit(list);
    this.brandSkeletons = new Map();
    for (const l of this.legit) if (!l.generic) this.brandSkeletons.set(l.skeletonLabel, l.registrable);
  }

  isLegit(host: string): boolean {
    for (const l of this.legit) if (isSameOrSubdomain(host, l.registrable)) return true;
    return false;
  }

  /** Analiza un hostname ASCII normalizado (ver normalizeHost). */
  analyze(rawHost: string): DomainVerdict {
    const host = stripCommonPrefix(rawHost);
    const unicodeHost = hostToUnicode(host);
    if (this.isLegit(host)) {
      return { host: rawHost, unicodeHost, risk: 'none', reasons: [], legit: true };
    }

    const reasons: DomainReason[] = [];
    const registrable = registrableDomain(host);
    const uRegistrable = hostToUnicode(registrable);
    const suffix = publicSuffix(host);
    const label = mainLabel(host);
    const uLabel = uRegistrable.split('.')[0] ?? uRegistrable;

    // 1. IDN / mezcla de alfabetos.
    const isIdn = host.split('.').some((p) => p.startsWith('xn--')) || hasNonAscii(unicodeHost);
    if (isIdn) {
      const labels = unicodeHost.split('.');
      if (labels.some(hasMixedScripts)) reasons.push({ code: 'mixed-script', risk: 'high' });
      else if (labels.some(isWholeScriptConfusable)) reasons.push({ code: 'mixed-script', risk: 'medium' });
      else reasons.push({ code: 'punycode', risk: 'low' });
    }

    // 2. Homoglifos: mismo "esqueleto" visual que un dominio legítimo.
    const skDomain = skeleton(uRegistrable);
    const skLabel = skeleton(uLabel);
    for (const l of this.legit) {
      if (registrable === l.registrable) continue;
      if (skDomain === l.skeletonDomain) {
        reasons.push({ code: 'homoglyph', risk: 'high', target: l.registrable });
        break;
      }
      if (!l.generic && skLabel === l.skeletonLabel && label !== l.label) {
        reasons.push({ code: 'homoglyph', risk: 'high', target: l.registrable });
        break;
      }
    }

    // 3. Typosquatting y cambio de extensión.
    if (!reasons.some((r) => r.code === 'homoglyph')) {
      for (const l of this.legit) {
        if (!l.generic) {
          if (label === l.label) {
            reasons.push({ code: 'tld-swap', risk: 'medium', target: l.registrable });
            break;
          }
          const tol = tolerance(l.label.length);
          if (tol > 0 && Math.abs(label.length - l.label.length) <= tol) {
            const d = boundedDistance(label, l.label, tol);
            if (d <= tol) {
              // Etiquetas cortas (5-6 letras) chocan con marcas reales ajenas
              // (zapier/zapper, rabb/rabby): ahí solo se marca riesgo medio.
              const risk: RiskLevel = d === 1 && l.label.length >= 7 ? 'high' : 'medium';
              reasons.push({ code: 'typosquat', risk, target: l.registrable });
              break;
            }
          }
        } else if (l.registrable.length >= 7) {
          // Marcas genéricas: solo comparar el dominio completo con 1 edición.
          const d = boundedDistance(registrable, l.registrable, 1);
          if (d === 1 && publicSuffix(l.registrable) !== suffix) {
            reasons.push({ code: 'typosquat', risk: 'medium', target: l.registrable });
            break;
          }
        }
      }
    }

    // 4. Marca combinada con palabras gancho, o marca en un subdominio ajeno.
    const tokens = unicodeHost.split(/[.\-_]/).filter(Boolean);
    const regTokens = new Set(uLabel.split(/[-_]/));
    const hasLure = tokens.some((t) => LURE_WORDS.has(t));
    for (const t of tokens) {
      const target = this.brandSkeletons.get(skeleton(t));
      if (!target) continue;
      if (regTokens.has(t) && uLabel !== t) {
        reasons.push({ code: 'brand-combo', risk: hasLure ? 'high' : 'medium', target });
      } else if (!regTokens.has(t)) {
        reasons.push({ code: 'brand-in-subdomain', risk: hasLure ? 'high' : 'low', target });
      }
      break;
    }

    // 5. Dominio legítimo completo incrustado como subdominio:
    //    "app.uniswap.org.secure-login.xyz" → el usuario lee "app.uniswap.org".
    const subPart = host.length > registrable.length ? host.slice(0, host.length - registrable.length) : '';
    for (const l of this.legit) {
      if (l.registrable.length < 6 || !subPart) continue;
      if (subPart.startsWith(`${l.registrable}.`) || subPart.includes(`.${l.registrable}.`)) {
        reasons.push({ code: 'brand-in-subdomain', risk: 'high', target: l.registrable });
        break;
      }
    }

    let risk: RiskLevel = 'none';
    for (const r of reasons) risk = maxRisk(risk, r.risk);
    return { host: rawHost, unicodeHost, risk, reasons, legit: false };
  }
}
