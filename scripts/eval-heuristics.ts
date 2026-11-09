/**
 * Evalúa las heurísticas de dominio contra datos reales:
 *  - falsos positivos: top-N dominios populares (no deberían marcarse "high")
 *  - cobertura: dominios de la blacklist de MetaMask detectados SOLO por heurística
 * Uso: npm run eval:heuristics -- <top-domains.txt> <metamask-config.json>
 */
import { readFileSync } from 'node:fs';
import { DomainAnalyzer } from '../shared/domain/typosquat';
import { normalizeHost } from '../shared/domain/normalize';

const [topPath, mmPath] = process.argv.slice(2);
if (!topPath || !mmPath) throw new Error('uso: eval-heuristics <top.txt> <config.json>');
const a = new DomainAnalyzer();

const top = readFileSync(topPath, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
const counts = { high: 0, medium: 0, low: 0, none: 0 };
const flagged: string[] = [];
let t0 = performance.now();
for (const d of top) {
  const h = normalizeHost(d);
  if (!h) continue;
  const v = a.analyze(h);
  counts[v.risk]++;
  if (v.risk === 'high' || v.risk === 'medium') flagged.push(`${v.risk} ${d} ${v.reasons.map((r) => r.code + ':' + (r.target ?? '')).join(',')}`);
}
const perDomainTop = (performance.now() - t0) / top.length;
console.log(`TOP ${top.length}:`, counts, `≈${(perDomainTop * 1000).toFixed(1)} µs/dominio`);
console.log(flagged.join('\n'));

const mm = JSON.parse(readFileSync(mmPath, 'utf8')) as { blacklist: string[] };
const c2 = { high: 0, medium: 0, low: 0, none: 0 };
t0 = performance.now();
for (const d of mm.blacklist) {
  const h = normalizeHost(d);
  if (!h) continue;
  c2[a.analyze(h).risk]++;
}
console.log(`BLACKLIST ${mm.blacklist.length}:`, c2, `≈${(((performance.now() - t0) / mm.blacklist.length) * 1000).toFixed(1)} µs/dominio`);
