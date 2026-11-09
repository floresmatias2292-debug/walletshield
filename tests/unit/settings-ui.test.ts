import { describe, expect, it } from 'vitest';
import { contentConfig, DEFAULT_SETTINGS, exportSettings, importSettings, parseSettings } from '../../shared/settings';
import { parseContentRequest, parsePrivilegedRequest } from '../../shared/messages';
import { parseTenderly, simulate } from '../../background/simulation';

const ME = '0x1111111111111111111111111111111111111111';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';

describe('exportar / importar', () => {
  it('ida y vuelta conserva la configuración y nunca incluye secretos', () => {
    const s = parseSettings({ ...DEFAULT_SETTINGS, strictness: 'strict', allowlist: ['app.uniswap.org'], simulation: { enabled: true, account: 'yo', project: 'p1' } });
    const file = exportSettings(s);
    expect(file).not.toMatch(/key/i);
    expect(importSettings(file)).toEqual(s);
  });
  it('rechaza archivos ajenos, inválidos o gigantes', () => {
    expect(() => importSettings('no json')).toThrow(/JSON/);
    expect(() => importSettings(JSON.stringify({ settings: {} }))).toThrow(/WalletShield/);
    expect(() => importSettings('x'.repeat(600 * 1024))).toThrow(/grande/);
  });
  it('limpia valores maliciosos en la importación', () => {
    const s = importSettings(JSON.stringify({ app: 'WalletShield', settings: { strictness: 'off', allowlist: ['<img src=x onerror=alert(1)>', 'jup.ag'], simulation: { enabled: true, account: '../../x', project: 'p' } } }));
    expect(s.strictness).toBe('normal');
    expect(s.allowlist).toEqual(['jup.ag']);
    expect(s.simulation.enabled).toBe(false);
  });
  it('la config para content scripts no lleva listas ni cuentas', () => {
    const c = contentConfig(parseSettings({ ...DEFAULT_SETTINGS, allowlist: ['a.com'], simulation: { enabled: true, account: 'a', project: 'b' } }));
    expect(c).toEqual({ strictness: 'normal', firewall: true, clipboardGuard: true, simulation: true });
  });
});

describe('mensajes de fase 6', () => {
  it('privilegiados', () => {
    expect(parsePrivilegedRequest({ type: 'lists:sync' })).toEqual({ type: 'lists:sync' });
    expect(parsePrivilegedRequest({ type: 'secret:set', key: 'abc_123' })).toEqual({ type: 'secret:set', key: 'abc_123' });
    expect(parsePrivilegedRequest({ type: 'secret:set', key: 'con espacio' })).toBeNull();
    expect(parsePrivilegedRequest({ type: 'secret:get' })).toBeNull(); // la key nunca se puede leer por mensaje
  });
  it('de content scripts', () => {
    expect(parseContentRequest({ type: 'cs:config' })).toEqual({ type: 'cs:config' });
    const ok = parseContentRequest({ type: 'sim:run', chainId: 1, blockNumber: 123, tx: { from: ME, to: USDC, value: '0x0', data: '0x095ea7b3' } });
    expect(ok?.type).toBe('sim:run');
    expect(parseContentRequest({ type: 'sim:run', chainId: 1, tx: { from: 'x', to: USDC, value: '0', data: '0x' } })).toBeNull();
    expect(parseContentRequest({ type: 'sim:run', chainId: 1, tx: { from: ME, to: USDC, value: '0', data: 'zz' } })).toBeNull();
  });
});

describe('simulación con Tenderly (formato del SDK oficial)', () => {
  const response = {
    status: true,
    logs: [
      { name: 'Transfer', inputs: [{ name: 'from', value: ME }, { name: 'to', value: '0x' + 'dd'.repeat(20) }, { name: 'value', value: '5000000' }], raw: { address: USDC } },
      { name: 'Transfer', inputs: [{ name: 'from', value: '0x' + 'ee'.repeat(20) }, { name: 'to', value: ME }, { name: 'value', value: '7' }], raw: { address: '0x' + 'cc'.repeat(20) } },
      { name: 'Approval', inputs: [{ name: 'owner', value: ME }, { name: 'spender', value: '0x' + 'bb'.repeat(20) }, { name: 'value', value: '1' }], raw: { address: USDC } },
      { name: 'Swap', inputs: [], raw: { address: USDC } },
    ],
  };
  it('deriva salidas, entradas y aprobaciones desde los logs', () => {
    const r = parseTenderly(response, ME);
    expect(r.ok).toBe(true);
    expect(r.changes?.map((c) => c.kind)).toEqual(['out', 'in', 'approval']);
    expect(r.changes?.[0]).toMatchObject({ token: USDC, amount: '5000000' });
  });
  it('revert y respuestas inesperadas', () => {
    expect(parseTenderly({ status: false, logs: [] }, ME).reverted).toBe(true);
    expect(parseTenderly({ foo: 1 }, ME).ok).toBe(false);
  });
  it('llama al endpoint v2 con la key en la cabecera y no envía credenciales', async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const f = (async (url: string, init: RequestInit) => {
      seen = { url, init };
      return new Response(JSON.stringify(response), { status: 200 });
    }) as unknown as typeof fetch;
    const r = await simulate({ account: 'acc', project: 'proj', key: 'k123' }, 1, 100, { from: ME, to: USDC, value: '0x0', data: '0x' }, f);
    expect(r.ok).toBe(true);
    expect(seen!.url).toBe('https://api.tenderly.co/api/v2/account/acc/project/proj/simulations/simulate');
    expect(new Headers(seen!.init.headers).get('x-access-key')).toBe('k123');
    expect(seen!.init.credentials).toBe('omit');
    const body = JSON.parse(String(seen!.init.body));
    expect(body).toMatchObject({ network_id: '1', call_args: { from: ME, to: USDC }, block_number_or_hash: { blockNumber: 100 } });
  });
  it('key inválida', async () => {
    const f = (async () => new Response('', { status: 403 })) as unknown as typeof fetch;
    expect((await simulate({ account: 'a', project: 'b', key: 'x' }, 1, null, { from: ME, to: USDC, value: '0', data: '0x' }, f)).error).toMatch(/inválida/);
  });
});
