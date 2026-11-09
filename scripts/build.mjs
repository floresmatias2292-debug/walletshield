// Build de la extensión con esbuild → dist/ (lo que se carga con "Cargar descomprimida").
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync, statSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const OUT = 'dist';
const dev = process.argv.includes('--dev');
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const common = {
  bundle: true,
  minify: !dev,
  sourcemap: dev ? 'inline' : false,
  target: 'chrome121',
  legalComments: 'none',
  logLevel: 'warning',
  define: { 'process.env.NODE_ENV': dev ? '"development"' : '"production"' },
};

await build({ ...common, entryPoints: ['background/index.ts'], outfile: `${OUT}/background/index.js`, format: 'esm' });
await build({ ...common, entryPoints: ['blocked/blocked.ts'], outfile: `${OUT}/blocked/blocked.js`, format: 'iife' });
await build({ ...common, entryPoints: ['popup/popup.ts'], outfile: `${OUT}/popup/popup.js`, format: 'iife' });
await build({ ...common, entryPoints: ['options/options.ts'], outfile: `${OUT}/options/options.js`, format: 'iife' });
await build({ ...common, entryPoints: ['content/main/index.ts'], outfile: `${OUT}/content/main.js`, format: 'iife' });
await build({ ...common, entryPoints: ['content/isolated/index.ts'], outfile: `${OUT}/content/isolated.js`, format: 'iife' });

for (const f of ['manifest.json', 'blocked/blocked.html', 'blocked/blocked.css', 'popup/popup.html', 'popup/popup.css', 'options/options.html', 'options/options.css', 'ui/base.css']) {
  mkdirSync(join(OUT, f, '..'), { recursive: true });
  cpSync(f, join(OUT, f));
}
cpSync('rules/static', `${OUT}/rules/static`, { recursive: true });
// Las listas empaquetadas se redistribuyen: se incluyen sus licencias.
cpSync('LICENSES', `${OUT}/LICENSES`, { recursive: true });
cpSync('LICENSE', `${OUT}/LICENSE`);
cpSync('icons', `${OUT}/icons`, { recursive: true, filter: (src) => !src.endsWith('.svg') });

function sizes(dir, acc = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) sizes(p, acc);
    else if (p.endsWith('.js')) acc.push([p, statSync(p).size]);
  }
  return acc;
}
for (const [p, s] of sizes(OUT)) console.log(`${p.padEnd(40)} ${(s / 1024).toFixed(1)} KB`);
