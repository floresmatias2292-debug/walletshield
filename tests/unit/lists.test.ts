import { describe, expect, it } from 'vitest';
import { sanitizeAll, sanitizeListDomain, sanitizeListPath, sanitizePaths } from '../../background/lists/sanitize';
import { parseMetaMask, parsePolkadot, parseScamSniffer } from '../../background/lists/parsers';
import {
  bucketOf, bucketize, bucketRuleIds, bucketsFromRules, diffDynamic, fnv1a, mergeAdditions,
  pathRule, planPaths, planSource, rulesForBucket, staticPathRules, STATIC_PATH_BASE, DYNAMIC_PATH_OFFSET,
} from '../../background/lists/buckets';
import { conditionalFetchJson } from '../../background/lists/fetcher';
import { parseRegistrationDate } from '../../background/rdap';

describe('sanitizeListDomain', () => {
  it('normaliza y acepta dominios de phishing reales', () => {
    expect(sanitizeListDomain(' OpenSeoa.App. ')).toBe('openseoa.app');
    expect(sanitizeListDomain('*.claim-paws.community')).toBe('claim-paws.community');
    expect(sanitizeListDomain('vote-polls3.pages.dev')).toBe('vote-polls3.pages.dev');
    expect(sanitizeListDomain('uniswаp.org')).toBe('xn--uniswp-7nf.org');
  });
  it('descarta plataformas compartidas encontradas en listas reales', () => {
    for (const d of ['sites.google.com', 'r2.dev', 'storage.googleapis.com', 'cloudflare-ipfs.com', 'pages.dev']) {
      expect(sanitizeListDomain(d)).toBeNull();
    }
  });
  it('descarta dominios legítimos y sus padres', () => {
    expect(sanitizeListDomain('app.uniswap.org')).toBeNull();
    expect(sanitizeListDomain('opensea.io')).toBeNull();
    expect(sanitizeListDomain('jup.ag')).toBeNull();
  });
  it('descarta basura', () => {
    for (const d of ['text', 'chromewebdata', 'ad', '', 42, null, 'a b.com', 'x.com:8080', 'foo.com/path']) {
      expect(sanitizeListDomain(d)).toBeNull();
    }
  });
  it('respeta allowlists de la fuente', () => {
    const allow = { exact: new Set(['ddns.net']), withSubdomains: new Set(['metamask.tools']) };
    expect(sanitizeListDomain('ddns.net', allow)).toBeNull();
    expect(sanitizeListDomain('evil.ddns.net', allow)).toBe('evil.ddns.net');
    expect(sanitizeListDomain('x.metamask.tools', allow)).toBeNull();
  });
  it('deduplica', () => {
    expect(sanitizeAll(['a-b.com', 'A-B.com', 'a-b.com.']).length).toBe(1);
  });
});

describe('rutas', () => {
  it('acepta páginas de Google Sites y rechaza comodines', () => {
    expect(sanitizeListPath('sites.google.com/view/metamask-microsoft/home')).toBe('sites.google.com/view/metamask-microsoft/home');
    expect(sanitizeListPath('https://sites.google.com/view/x1/?q=1')).toBe('sites.google.com/view/x1');
    expect(sanitizeListPath('sites.google.com/view/*')).toBeNull();
    expect(sanitizeListPath('sites.google.com/a|b')).toBeNull();
    expect(sanitizeListPath('opensea.io/collection/fake')).toBeNull(); // sitio legítimo: no se toca
    expect(sanitizePaths(['plain.com', 'twitter.com/AcalaNetworks'])).toEqual(['twitter.com/AcalaNetworks']);
  });
  it('genera urlFilter anclado', () => {
    expect(pathRule(5, 'sites.google.com/view/a').condition.urlFilter).toBe('||sites.google.com/view/a^');
  });
  it('planPaths: bajas deshabilitan estáticas, altas van a dinámicas', () => {
    const stat = staticPathRules(['h.com/a', 'h.com/b']);
    const plan = planPaths(stat, [], ['h.com/a', 'h.com/c'], 10_000);
    expect(plan.disableStaticRuleIds).toEqual([STATIC_PATH_BASE + 1]);
    expect(plan.diff.addRules.map((r) => r.condition.urlFilter)).toEqual(['||h.com/c^']);
    expect(plan.diff.addRules[0]!.id).toBe(10_000 + DYNAMIC_PATH_OFFSET);
    // Idempotente: aplicar el plan y recalcular no produce cambios.
    const again = planPaths(stat, plan.diff.addRules, ['h.com/a', 'h.com/c'], 10_000);
    expect(again.diff.addRules).toEqual([]);
    expect(again.diff.removeRuleIds).toEqual([]);
  });
});

describe('parsers', () => {
  it('MetaMask', () => {
    const p = parseMetaMask({ version: '2', blacklist: ['a.com'], whitelist: ['metamask.io', 3] });
    expect(p.block).toEqual(['a.com']);
    expect(p.allowWithSubdomains).toEqual(['metamask.io']);
    expect(() => parseMetaMask({})).toThrow();
  });
  it('polkadot', () => {
    const p = parsePolkadot({ allow: ['*.fleek.co'], deny: ['x.com'], denySub: ['twitter.com/x'] });
    expect(p.allowExact).toEqual(['fleek.co']);
    expect(p.blockPaths).toEqual(['twitter.com/x']);
  });
  it('ScamSniffer completo y archivo diario', () => {
    expect(parseScamSniffer(['a.com']).block).toEqual(['a.com']);
    expect(parseScamSniffer({ domains: ['b.com'] }).block).toEqual(['b.com']);
    expect(() => parseScamSniffer('x')).toThrow();
  });
});

describe('buckets y diff de reglas', () => {
  it('hash estable', () => {
    expect(fnv1a('openseoa.app')).toBe(fnv1a('openseoa.app'));
    expect(bucketOf('openseoa.app', 128)).toBeLessThan(128);
  });
  it('reglas de un bucket: redirect (navegación) + block (subrecursos)', () => {
    const [r, b] = rulesForBucket(30_000, 3, ['x.com', 'y.com']);
    expect(r!.id).toBe(30_006);
    expect(r!.action.type).toBe('redirect');
    expect(r!.condition.resourceTypes).toEqual(['main_frame']);
    expect(b!.id).toBe(30_007);
    expect(b!.condition.resourceTypes).toContain('script');
    expect(rulesForBucket(0, 0, [])).toEqual([]);
  });
  it('planSource: igual / altas / bajas', () => {
    const snap = [['a.com', 'b.com'], ['c.com'], ['d.com']];
    const cur = [['a.com', 'b.com'], ['c.com', 'z.com'], []];
    const plan = planSource(snap, cur);
    expect(plan.dynamicBuckets.get(0)).toBeUndefined(); // sin cambios
    expect(plan.dynamicBuckets.get(1)).toEqual(['z.com']); // solo la alta
    expect(plan.disableStaticRuleIds).toEqual(bucketRuleIds(1, 2)); // baja → estática off
    expect(plan.dynamicBuckets.get(2)).toBeUndefined();
  });
  it('planSource sin snapshot: todo dinámico', () => {
    const plan = planSource(null, [['a.com'], []]);
    expect([...plan.dynamicBuckets.keys()]).toEqual([0]);
  });
  it('diffDynamic solo toca buckets cambiados y es idempotente', () => {
    const base = 30_000;
    const existing = [...rulesForBucket(base, 0, ['a.com']), ...rulesForBucket(base, 1, ['b.com'])];
    const desired = new Map([[0, ['a.com']], [2, ['c.com']]]);
    const d = diffDynamic(base, 4, existing, desired);
    expect(d.removeRuleIds.sort()).toEqual(bucketRuleIds(base, 1));
    expect(d.addRules.map((r) => r.id)).toEqual(bucketRuleIds(base, 2));
    const after = [...rulesForBucket(base, 0, ['a.com']), ...d.addRules];
    const d2 = diffDynamic(base, 4, after, desired);
    expect(d2.addRules).toEqual([]);
    expect(d2.removeRuleIds).toEqual([]);
  });
  it('mergeAdditions devuelve solo buckets tocados con contenido nuevo', () => {
    const n = 8;
    const existing = new Map([[bucketOf('a.com', n), ['a.com']]]);
    const touched = mergeAdditions(existing, ['a.com', 'new-one.com'], n);
    const b = bucketOf('new-one.com', n);
    expect(touched.get(b)).toContain('new-one.com');
    if (b !== bucketOf('a.com', n)) expect(touched.has(bucketOf('a.com', n))).toBe(false);
  });
  it('bucketsFromRules reconstruye lo escrito', () => {
    const rules = bucketize(['a.com', 'b.com', 'c.com'], 4).flatMap((b, i) => rulesForBucket(100, i, b));
    const back = bucketsFromRules(100, 4, rules);
    expect([...back.values()].flat().sort()).toEqual(['a.com', 'b.com', 'c.com']);
  });
});

describe('descarga condicional', () => {
  const ok = (body: string, headers: Record<string, string> = {}) =>
    (async () => new Response(body, { status: 200, headers })) as unknown as typeof fetch;
  it('envía ETag / If-Modified-Since y entiende 304', async () => {
    let seen: Headers | undefined;
    const f = (async (_u: string, init?: RequestInit) => {
      seen = new Headers(init?.headers);
      return new Response(null, { status: 304 });
    }) as unknown as typeof fetch;
    const r = await conditionalFetchJson('https://x.test/l.json', { etag: '"abc"', lastModified: 'Mon' }, f);
    expect(r.status).toBe('not-modified');
    expect(seen?.get('if-none-match')).toBe('"abc"');
    expect(seen?.get('if-modified-since')).toBe('Mon');
  });
  it('200 devuelve JSON y nuevo ETag', async () => {
    const r = await conditionalFetchJson('https://x.test/l.json', undefined, ok('["a.com"]', { etag: '"n"' }));
    expect(r).toMatchObject({ status: 'ok', json: ['a.com'], meta: { etag: '"n"' } });
  });
  it('rechaza HTTP plano, JSON inválido y respuestas gigantes', async () => {
    await expect(conditionalFetchJson('http://x.test/l.json', undefined, ok('[]'))).rejects.toThrow();
    await expect(conditionalFetchJson('https://x.test/l.json', undefined, ok('alert(1)'))).rejects.toThrow();
    await expect(
      conditionalFetchJson('https://x.test/l.json', undefined, ok('[]', { 'content-length': String(64 * 1024 * 1024) })),
    ).rejects.toThrow(/grande/);
  });
  it('404 → not-found', async () => {
    const f = (async () => new Response('', { status: 404 })) as unknown as typeof fetch;
    expect((await conditionalFetchJson('https://x.test/a', undefined, f)).status).toBe('not-found');
  });
});

describe('RDAP', () => {
  it('extrae la fecha de registro', () => {
    const t = parseRegistrationDate({ events: [{ eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' }, { eventAction: 'registration', eventDate: '2026-11-01T00:00:00Z' }] });
    expect(t).toBe(Date.parse('2026-11-01T00:00:00Z'));
    expect(parseRegistrationDate({ events: 'x' })).toBeNull();
    expect(parseRegistrationDate(null)).toBeNull();
  });
});
