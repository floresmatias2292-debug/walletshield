import type { DomainReason, DomainReasonCode } from './domain/typosquat';
import type { RiskLevel } from './risk';

export const RISK_LABEL: Record<RiskLevel, string> = {
  none: 'Sin riesgo detectado',
  low: 'Riesgo bajo',
  medium: 'Riesgo medio',
  high: 'Riesgo alto',
};

const REASON: Record<DomainReasonCode, (target?: string) => string> = {
  homoglyph: (t) => `La dirección se ve casi idéntica a ${t ?? 'un sitio conocido'} pero usa letras distintas (homoglifos).`,
  'mixed-script': () => 'El nombre mezcla letras de distintos alfabetos (por ejemplo latinas y cirílicas), un truco típico para imitar sitios.',
  punycode: () => 'Es un dominio internacionalizado (IDN). Revisa con cuidado cada letra.',
  typosquat: (t) => `El nombre está a una o dos letras de ${t ?? 'un sitio conocido'} (typosquatting).`,
  'tld-swap': (t) => `Usa el nombre de ${t ?? 'un sitio conocido'} con otra extensión. El sitio oficial es ${t ?? 'otro'}.`,
  'brand-combo': (t) => `Combina la marca de ${t ?? 'un sitio conocido'} con otras palabras ("claim", "airdrop"…), patrón frecuente de drainers.`,
  'brand-in-subdomain': (t) => `Usa ${t ?? 'una marca conocida'} como subdominio de un sitio que no es el oficial.`,
  'new-domain': () => 'El dominio se registró hace menos de 30 días.',
};

export function reasonText(r: DomainReason): string {
  return REASON[r.code](r.target);
}
