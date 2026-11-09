/** Cliente JSON-RPC mínimo con lotes (batch) y timeout. */
export class RpcError extends Error {}

const TIMEOUT_MS = 15_000;
let nextId = 1;

export interface Call {
  readonly method: string;
  readonly params: unknown[];
}

export async function rpcBatch(url: string, calls: readonly Call[], fetchImpl: typeof fetch = fetch): Promise<unknown[]> {
  if (calls.length === 0) return [];
  const reqs = calls.map((c) => ({ jsonrpc: '2.0', id: nextId++, method: c.method, params: c.params }));
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(reqs.length === 1 ? reqs[0] : reqs),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new RpcError(`HTTP ${res.status} en ${new URL(url).host}`);
  const json = (await res.json()) as unknown;
  const arr = Array.isArray(json) ? json : [json];
  const byId = new Map<number, { result?: unknown; error?: { message?: string } }>();
  for (const r of arr) if (r && typeof r === 'object') byId.set((r as { id: number }).id, r as { result?: unknown; error?: { message?: string } });
  return reqs.map((q) => {
    const r = byId.get(q.id);
    if (!r) throw new RpcError(`sin respuesta para ${q.method}`);
    if (r.error) throw new RpcError(`${q.method}: ${String(r.error.message ?? 'error').slice(0, 160)}`);
    return r.result;
  });
}

export async function rpc(url: string, method: string, params: unknown[], fetchImpl: typeof fetch = fetch): Promise<unknown> {
  return (await rpcBatch(url, [{ method, params }], fetchImpl))[0];
}
