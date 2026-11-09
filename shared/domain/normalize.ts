/**
 * Normalización de hostnames y cálculo aproximado del "dominio registrable".
 *
 * No se incluye la Public Suffix List completa (más de 200 KB) para mantener
 * el bundle chico: se usa un subconjunto con los sufijos multinivel más
 * comunes y los servicios de hosting gratuito que más usan los phishers
 * (en ellos cada subdominio pertenece a una persona distinta).
 */

const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar',
  'com.br', 'net.br', 'org.br',
  'com.mx', 'org.mx', 'com.co', 'com.pe', 'com.ve', 'com.uy', 'com.ec', 'cl.cl',
  'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 'co.in', 'co.id',
  'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'or.kr', 'com.cn', 'net.cn', 'org.cn',
  'com.hk', 'com.tw', 'com.sg', 'com.my', 'com.ph', 'com.vn', 'com.tr', 'com.ua',
  'com.ru', 'com.es', 'com.pl', 'co.il', 'com.ng', 'com.pk', 'com.bd', 'com.eg',
  'eu.org', 'us.com', 'uk.com',
]);

/**
 * Plataformas donde cada subdominio es un sitio independiente. Se tratan como
 * sufijos públicos: "uniswap-claim.pages.dev" tiene como dominio registrable
 * "uniswap-claim.pages.dev" y como etiqueta "uniswap-claim".
 */
export const HOSTING_SUFFIXES = new Set([
  'pages.dev', 'workers.dev', 'r2.dev', 'vercel.app', 'now.sh', 'netlify.app', 'netlify.com',
  'github.io', 'gitlab.io', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'onrender.com',
  'fly.dev', 'railway.app', 'up.railway.app', 'replit.app', 'repl.co', 'glitch.me', 'surge.sh',
  'webflow.io', 'wixsite.com', 'weebly.com', 'blogspot.com', 'wordpress.com', 'godaddysites.com',
  'square.site', 'typedream.app', 'framer.website', 'framer.app', 'notion.site', 'gitbook.io',
  'myshopify.com', 'carrd.co', 'amplifyapp.com', 'azurewebsites.net', 'appspot.com',
  'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'on-fleek.app', 'fleek.co', 'on.fleek.co',
  '4everland.app', 'ipfs.dweb.link', 'eth.limo', 'eth.link', 'ddns.net', 'duckdns.org',
  'hopto.org', 'zapto.org', 'sytes.net', 'servehttp.com', '000webhostapp.com', 'webcindario.com',
  'translate.goog', 'b-cdn.net', 'pinata.cloud', 'mypinata.cloud', 'firebasestorage.app',
  'cloudfront.net', 'trycloudflare.com', 'deno.dev', 'val.run', 'render.com', 'pantheonsite.io',
  'sites.google.com', 'storage.googleapis.com', 's3.amazonaws.com', 'cloudflare-ipfs.com',
]);

const HOST_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/;

/** Hostname en minúsculas y sin punto final. Devuelve null si la URL no es http(s). */
export function hostnameFromUrl(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  return normalizeHost(u.hostname);
}

export function normalizeHost(host: string): string | null {
  let h = host.trim().toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (h.startsWith('[') || /^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return null; // IPs: sin análisis de dominio
  return HOST_RE.test(h) ? h : null;
}

/** Quita prefijos "www." (y variantes "m.") que no aportan al análisis. */
export function stripCommonPrefix(host: string): string {
  return host.replace(/^(www\d?|m)\./, '');
}

export function isValidHostname(host: string): boolean {
  return HOST_RE.test(host);
}

/** Devuelve el sufijo público más largo conocido que termina el host. */
export function publicSuffix(host: string): string {
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const candidate = parts.slice(i).join('.');
    if (HOSTING_SUFFIXES.has(candidate) || MULTI_PART_SUFFIXES.has(candidate)) {
      // Si el host ES el sufijo (p. ej. "pages.dev") se toma su propia TLD.
      return i === 0 ? parts.slice(1).join('.') : candidate;
    }
  }
  return parts[parts.length - 1] ?? host;
}

/** eTLD+1 aproximado: "app.uniswap.org" → "uniswap.org". */
export function registrableDomain(host: string): string {
  const suffix = publicSuffix(host);
  if (host === suffix) return host;
  const rest = host.slice(0, host.length - suffix.length - 1);
  const label = rest.split('.').pop() ?? rest;
  return `${label}.${suffix}`;
}

/** Etiqueta principal del dominio registrable: "app.uniswap.org" → "uniswap". */
export function mainLabel(host: string): string {
  const reg = registrableDomain(host);
  return reg.split('.')[0] ?? reg;
}

/** true si host es igual a parent o es un subdominio de parent. */
export function isSameOrSubdomain(host: string, parent: string): boolean {
  return host === parent || host.endsWith(`.${parent}`);
}

/** Recorre host y todos sus dominios padre (sin incluir la TLD sola). */
export function* hostAndParents(host: string): Generator<string> {
  let h = host;
  while (h.includes('.')) {
    yield h;
    h = h.slice(h.indexOf('.') + 1);
  }
}
