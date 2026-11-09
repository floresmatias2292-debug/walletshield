export type RiskLevel = 'none' | 'low' | 'medium' | 'high';

const ORDER: Record<RiskLevel, number> = { none: 0, low: 1, medium: 2, high: 3 };

export function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return ORDER[a] >= ORDER[b] ? a : b;
}

export function riskAtLeast(level: RiskLevel, threshold: RiskLevel): boolean {
  return ORDER[level] >= ORDER[threshold];
}

export type Strictness = 'relaxed' | 'normal' | 'strict';

/** Riesgo mínimo de dominio a partir del cual se muestra la página de advertencia. */
export function domainInterstitialThreshold(s: Strictness): RiskLevel {
  switch (s) {
    case 'relaxed':
      return 'high';
    case 'normal':
      return 'high';
    case 'strict':
      return 'medium';
  }
}
