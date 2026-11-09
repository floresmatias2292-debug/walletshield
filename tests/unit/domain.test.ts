import { describe, expect, it } from 'vitest';
import { DomainAnalyzer } from '../../shared/domain/typosquat';
import { boundedDistance } from '../../shared/domain/levenshtein';
import { decodePunycodeLabel, hostToUnicode } from '../../shared/domain/punycode';
import { hasMixedScripts, skeleton } from '../../shared/domain/homoglyph';
import { hostnameFromUrl, registrableDomain, mainLabel } from '../../shared/domain/normalize';
import { LEGIT_DOMAINS } from '../../shared/domain/legit-domains';

const a = new DomainAnalyzer();

describe('normalize', () => {
  it('extrae hostname solo de http(s)', () => {
    expect(hostnameFromUrl('https://App.Uniswap.org./swap')).toBe('app.uniswap.org');
    expect(hostnameFromUrl('chrome://settings')).toBeNull();
    expect(hostnameFromUrl('https://192.168.0.1/')).toBeNull();
  });
  it('dominio registrable con sufijos multinivel y hosting', () => {
    expect(registrableDomain('app.uniswap.org')).toBe('uniswap.org');
    expect(registrableDomain('shop.example.com.ar')).toBe('example.com.ar');
    expect(registrableDomain('uniswap-claim.pages.dev')).toBe('uniswap-claim.pages.dev');
    expect(mainLabel('x.uniswap-claim.vercel.app')).toBe('uniswap-claim');
  });
});

describe('punycode', () => {
  it('decodifica vectores RFC 3492 y casos reales', () => {
    expect(decodePunycodeLabel('mnchen-3ya')).toBe('münchen');
    expect(hostToUnicode('xn--80ak6aa92e.com')).toBe('аррӏе.com'); // homógrafo clásico de apple.com
    expect(hostToUnicode('xn--uniswp-7nf.org')).toBe('uniswаp.org'); // "а" cirílica
    expect(decodePunycodeLabel('!!!')).toBeNull();
  });
});

describe('homoglifos y distancia', () => {
  it('esqueleto iguala variantes visuales', () => {
    expect(skeleton('uniswаp')).toBe(skeleton('uniswap')); // cirílica
    expect(skeleton('0pensea')).toBe(skeleton('opensea'));
    expect(skeleton('metarnask')).toBe(skeleton('metamask'));
    expect(skeleton('rnetamask')).toBe(skeleton('metamask'));
    expect(skeleton('ùniswap')).toBe(skeleton('uniswap'));
  });
  it('mezcla de alfabetos', () => {
    expect(hasMixedScripts('uniswаp')).toBe(true);
    expect(hasMixedScripts('münchen')).toBe(false);
  });
  it('Damerau-Levenshtein acotado', () => {
    expect(boundedDistance('uniswap', 'uniswap', 2)).toBe(0);
    expect(boundedDistance('uinswap', 'uniswap', 2)).toBe(1); // transposición
    expect(boundedDistance('unisvvap', 'uniswap', 2)).toBe(2);
    expect(boundedDistance('opensea', 'kitties', 2)).toBe(3); // corte temprano → max+1
  });
  it('ningún par de dominios legítimos colisiona por esqueleto', () => {
    const seen = new Map<string, string>();
    for (const { domain } of LEGIT_DOMAINS) {
      const reg = registrableDomain(domain);
      const sk = skeleton(reg);
      const prev = seen.get(sk);
      if (prev && prev !== reg) throw new Error(`${prev} y ${reg} colisionan`);
      seen.set(sk, reg);
    }
  });
});

describe('DomainAnalyzer: sitios legítimos (sin falsos positivos)', () => {
  const legit = [
    'app.uniswap.org', 'uniswap.org', 'opensea.io', 'jup.ag', 'station.jup.ag', 'raydium.io',
    'pro.opensea.io', 'app.aave.com', 'etherscan.io', 'arbiscan.io', 'revoke.cash', 'magiceden.io',
    'www.coinbase.com', 'portal.arbitrum.io', 'swap.cow.fi', 'stake.lido.fi', 'curve.finance',
  ];
  for (const h of legit) {
    it(h, () => {
      const v = a.analyze(h);
      expect(v.legit).toBe(true);
      expect(v.risk).toBe('none');
    });
  }
  const unrelated = [
    'google.com', 'wikipedia.org', 'github.com', 'amazon.com', 'mercadolibre.com.ar', 'clarin.com',
    'safe.com', 'blur.com', 'sushi.com.ar', 'gmx.com', 'curve.com', 'base.com', 'drift.com', 'sky.com',
    'zapier.com', 'medium.com', 'uniswap.medium.com', 'jupyter.org', 'raydiance.com', 'openai.com',
    'phantomjs.org', 'ledger.fr', 'münchen.de',
  ];
  for (const h of unrelated) {
    it(`${h} no se marca alto`, () => {
      const v = a.analyze(h.includes('ü') ? 'xn--mnchen-3ya.de' : h);
      expect(v.risk === 'high').toBe(false);
    });
  }
});

describe('DomainAnalyzer: imitaciones (casos reales de la blacklist de MetaMask y patrones conocidos)', () => {
  const cases: Array<[string, string, string]> = [
    // [host, riesgo mínimo esperado, motivo]
    ['openseoa.app', 'high', 'typosquat'], // real: eth-phishing-detect
    ['opencea.mom', 'high', 'typosquat'], // real: eth-phishing-detect
    ['opensea.support', 'medium', 'tld-swap'], // real: eth-phishing-detect
    ['xn--uniswp-7nf.org', 'high', 'homoglyph'], // uniswаp.org con "а" cirílica
    ['xn--opnsea-4of.io', 'high', 'homoglyph'], // opеnsea.io con "е" cirílica
    ['0pensea.io', 'high', 'homoglyph'],
    ['metarnask.io', 'high', 'homoglyph'],
    ['uniswap-claim.com', 'high', 'brand-combo'],
    ['claim-uniswap.pages.dev', 'high', 'brand-combo'],
    ['raydium-airdrop.xyz', 'high', 'brand-combo'],
    ['app.uniswap.org.secure-login.xyz', 'high', 'brand-in-subdomain'],
    ['uniswap.claim-rewards.xyz', 'high', 'brand-in-subdomain'],
    ['uniswap.app', 'medium', 'tld-swap'],
    ['uinswap.org', 'high', 'typosquat'],
    ['raydlum.io', 'high', 'homoglyph'],
    ['jupiter-ag.com', 'none', ''], // marca genérica: no se adivina
  ];
  const order = { none: 0, low: 1, medium: 2, high: 3 } as const;
  for (const [host, min, code] of cases) {
    it(`${host} → ≥${min} (${code || 'sin motivo'})`, () => {
      const v = a.analyze(host);
      expect(order[v.risk]).toBeGreaterThanOrEqual(order[min as keyof typeof order]);
      if (code) expect(v.reasons.map((r) => r.code)).toContain(code);
    });
  }
  it('analiza en menos de 0,5 ms por dominio', () => {
    const t0 = performance.now();
    for (let i = 0; i < 2000; i++) a.analyze(`random-site-${i}.example.com`);
    expect((performance.now() - t0) / 2000).toBeLessThan(0.5);
  });
});
