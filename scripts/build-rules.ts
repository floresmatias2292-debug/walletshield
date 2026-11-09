/**
 * Genera el snapshot estático de reglas DNR (rules/static/*.json) a partir de
 * las listas con licencia que permite redistribución (MetaMask DBAD-1.2 y
 * polkadot-js Apache-2.0). ScamSniffer (GPL-3.0) NO se empaqueta.
 *
 * Uso: npm run build:rules            (descarga las listas)
 *      npm run build:rules -- <dir>   (usa <dir>/mm.json y <dir>/pd.json)
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { SOURCES, type SourceId } from '../background/lists/sources';
import { PARSERS } from '../background/lists/parsers';
import { sanitizeAll, sanitizePaths } from '../background/lists/sanitize';
import { bucketize, rulesForBucket, staticPathRules } from '../background/lists/buckets';

const dir = process.argv[2];
const files: Partial<Record<SourceId, string>> = { metamask: 'mm.json', polkadot: 'pd.json' };

async function load(id: SourceId): Promise<{ text: string; etag: string | null }> {
  if (dir) return { text: readFileSync(`${dir}/${files[id]}`, 'utf8'), etag: null };
  const res = await fetch(SOURCES[id].url);
  if (!res.ok) throw new Error(`${id}: HTTP ${res.status}`);
  return { text: await res.text(), etag: res.headers.get('etag') };
}

mkdirSync('rules/static', { recursive: true });
const meta: Record<string, unknown> = { generatedAt: new Date().toISOString(), sources: {} };
let upstreamAllow: string[] = [];

for (const id of ['metamask', 'polkadot'] as const) {
  const src = SOURCES[id];
  const { text, etag } = await load(id);
  const parsed = PARSERS[id](JSON.parse(text) as unknown);
  if (id === 'metamask') upstreamAllow = [...parsed.allowWithSubdomains];
  const domains = sanitizeAll(parsed.block, {
    exact: new Set(parsed.allowExact),
    withSubdomains: new Set([...parsed.allowWithSubdomains, ...upstreamAllow]),
  });
  const buckets = bucketize(domains, src.buckets);
  const paths = sanitizePaths([...parsed.block, ...parsed.blockPaths]);
  const rules = [...buckets.flatMap((b, i) => rulesForBucket(1, i, b)), ...staticPathRules(paths)];
  writeFileSync(`rules/static/${src.staticRuleset}.json`, JSON.stringify(rules));
  (meta.sources as Record<string, unknown>)[id] = {
    url: src.url,
    license: src.license,
    raw: parsed.block.length,
    kept: domains.length,
    discarded: parsed.block.length - domains.length,
    paths: paths.length,
    rules: rules.length,
    maxDomainsPerRule: Math.max(...buckets.map((b) => b.length)),
    sha256: createHash('sha256').update(text).digest('hex'),
    etag,
  };
  console.log(`${id}: ${parsed.block.length} → ${domains.length} dominios + ${paths.length} rutas, ${rules.length} reglas`);
}
meta.upstreamAllow = upstreamAllow;
writeFileSync('rules/static/meta.json', JSON.stringify(meta, null, 2));
