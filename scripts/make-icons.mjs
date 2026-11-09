// Genera icons/icon-{16,32,48,128}.png desde icons/icon.svg con Chromium (Playwright).
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
const { chromium } = createRequire(import.meta.url)('playwright');
const svg = readFileSync('icons/icon.svg', 'utf8');
const browser = await chromium.launch();
for (const size of [16, 32, 48, 128]) {
  const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
  await page.setContent(`<style>html,body{margin:0;background:transparent}</style>${svg.replace('<svg ', `<svg width="${size}" height="${size}" `)}`);
  await page.screenshot({ path: `icons/icon-${size}.png`, omitBackground: true });
  await page.close();
}
await browser.close();
