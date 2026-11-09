/**
 * Descarga condicional con ETag / If-Modified-Since: si la lista no cambió,
 * el servidor responde 304 y no se transfiere nada.
 */
export interface FetchMeta {
  etag?: string;
  lastModified?: string;
}

export type ConditionalResult =
  | { status: 'not-modified' }
  | { status: 'not-found' }
  | { status: 'ok'; json: unknown; meta: FetchMeta; bytes: number };

const MAX_BYTES = 32 * 1024 * 1024;
const TIMEOUT_MS = 60_000;

export async function conditionalFetchJson(
  url: string,
  meta: FetchMeta | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<ConditionalResult> {
  if (!url.startsWith('https://')) throw new Error('solo se permiten descargas HTTPS');
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (meta?.etag) headers['If-None-Match'] = meta.etag;
  if (meta?.lastModified) headers['If-Modified-Since'] = meta.lastModified;

  const res = await fetchImpl(url, {
    headers,
    cache: 'no-cache',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    redirect: 'follow',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (res.status === 304) return { status: 'not-modified' };
  if (res.status === 404) return { status: 'not-found' };
  if (!res.ok) throw new Error(`HTTP ${res.status} en ${url}`);

  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BYTES) throw new Error(`lista demasiado grande (${declared} bytes)`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error('lista demasiado grande');

  const newMeta: FetchMeta = {};
  const etag = res.headers.get('etag');
  const lm = res.headers.get('last-modified');
  if (etag) newMeta.etag = etag;
  if (lm) newMeta.lastModified = lm;
  // JSON.parse: nunca eval. Si el contenido no es JSON válido, falla.
  return { status: 'ok', json: JSON.parse(text) as unknown, meta: newMeta, bytes: text.length };
}
