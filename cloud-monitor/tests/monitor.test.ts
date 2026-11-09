import { describe, expect, it } from 'vitest';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { loadConfig } from '../src/config';
import { T } from '../src/evm';
import { runMonitor } from '../src/index';
import { escapeHtml, formatAlerts } from '../src/telegram';
import type { Env, KV } from '../src/types';

const ME = '0x1111111111111111111111111111111111111111';
const DRAINER = '0xd4a1e2000000000000000000000000000000dead';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const UR = '0x66a9893cc07d91d95644aedd05d03f95e1dba8af';
const BAYC = '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d';
const SOL_ME = '7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV';
const pad = (a: string) => `0x${a.slice(2).padStart(64, '0')}`;
const u256 = (v: bigint) => `0x${v.toString(16).padStart(64, '0')}`;
const MAX = (1n << 256n) - 1n;

class MemKV implements KV {
  m = new Map<string, string>();
  async get(k: string) { return this.m.get(k) ?? null; }
  async put(k: string, v: string) { this.m.set(k, v); }
}

interface World {
  block: Record<string, number>;
  nonce: Record<string, number>;
  logs: Record<string, unknown[]>;
  getLogsCalls: Array<{ host: string; from: number; to: number }>;
  rpcDown: Set<string>;
  telegram: string[];
  telegramDown: boolean;
  sol: { sigs: Array<{ signature: string }>; txs: Record<string, unknown> };
}

function world(): World {
  return { block: { eth: 1000, arb: 50_000 }, nonce: { eth: 5, arb: 2 }, logs: { eth: [], arb: [] }, getLogsCalls: [], rpcDown: new Set(), telegram: [], telegramDown: false, sol: { sigs: [], txs: {} } };
}

function fakeFetch(w: World): typeof fetch {
  return (async (url: string, init: RequestInit) => {
    const u = new URL(url);
    if (u.host === 'tg.test') {
      if (w.telegramDown) return new Response('{}', { status: 500 });
      w.telegram.push(JSON.parse(String(init.body)).text);
      return new Response('{"ok":true}', { status: 200 });
    }
    const net = u.host.split('.')[0]!; // eth | arb | sol
    if (w.rpcDown.has(net)) return new Response('down', { status: 503 });
    const body = JSON.parse(String(init.body));
    const reqs = Array.isArray(body) ? body : [body];
    const out = reqs.map((r: { id: number; method: string; params: unknown[] }) => {
      let result: unknown = null;
      switch (r.method) {
        case 'eth_blockNumber': result = `0x${w.block[net]!.toString(16)}`; break;
        case 'eth_getTransactionCount': result = `0x${w.nonce[net]!.toString(16)}`; break;
        case 'eth_getLogs': {
          const f = r.params[0] as { fromBlock: string; toBlock: string };
          const from = parseInt(f.fromBlock, 16);
          const to = parseInt(f.toBlock, 16);
          w.getLogsCalls.push({ host: net, from, to });
          result = (w.logs[net] ?? []).filter((l) => { const b = (l as { b: number }).b; return b >= from && b <= to; });
          break;
        }
        case 'getSignaturesForAddress': {
          const opts = r.params[1] as { until?: string };
          const idx = opts.until ? w.sol.sigs.findIndex((s) => s.signature === opts.until) : -1;
          result = idx >= 0 ? w.sol.sigs.slice(0, idx) : w.sol.sigs;
          break;
        }
        case 'getTransaction': result = w.sol.txs[r.params[0] as string] ?? null; break;
      }
      return { jsonrpc: '2.0', id: r.id, result };
    });
    return new Response(JSON.stringify(Array.isArray(body) ? out : out[0]), { status: 200 });
  }) as unknown as typeof fetch;
}

function env(kv: KV, over: Partial<Env> = {}): Env {
  return {
    STATE: kv, EVM_ADDRESSES: ME, SOLANA_ADDRESSES: '', EVM_CHAINS: '1,42161',
    ETH_RPC_URL: 'https://eth.rpc.test', ARB_RPC_URL: 'https://arb.rpc.test', SOL_RPC_URL: 'https://sol.rpc.test',
    TELEGRAM_BOT_TOKEN: '123:SECRET', TELEGRAM_CHAT_ID: '42', TELEGRAM_API_BASE: 'https://tg.test', ...over,
  };
}

const log = (b: number, address: string, topics: string[], data = '0x', tx = '0xabc') => ({ b, address, topics, data, transactionHash: tx });

describe('configuración segura', () => {
  it('acepta direcciones públicas válidas', () => {
    const c = loadConfig(env(new MemKV(), { SOLANA_ADDRESSES: SOL_ME }));
    expect(c.evm).toEqual([ME]);
    expect(c.solana).toEqual([SOL_ME]);
    expect(c.chains.map((x) => x.name)).toEqual(['Ethereum', 'Arbitrum']);
  });
  it('se niega a correr con una clave privada o una frase semilla', () => {
    expect(() => loadConfig(env(new MemKV(), { EVM_ADDRESSES: '0x' + 'ab'.repeat(32) }))).toThrow(/CLAVE PRIVADA/);
    expect(() => loadConfig(env(new MemKV(), { EVM_ADDRESSES: 'abandon ability able about above absent absorb abstract absurd abuse access accident' }))).toThrow(/FRASE SEMILLA/);
    expect(() => loadConfig(env(new MemKV(), { EVM_ADDRESSES: '0x123' }))).toThrow(/inválidas/);
    expect(() => loadConfig(env(new MemKV(), { EVM_CHAINS: '56' }))).toThrow(/no soportada/);
  });
  it('hashes de eventos correctos (keccak256)', () => {
    const k = (s: string) => `0x${Buffer.from(keccak_256(new TextEncoder().encode(s))).toString('hex')}`;
    expect(T.transfer).toBe(k('Transfer(address,address,uint256)'));
    expect(T.approval).toBe(k('Approval(address,address,uint256)'));
    expect(T.approvalForAll).toBe(k('ApprovalForAll(address,address,bool)'));
    expect(T.permit2Approval).toBe(k('Approval(address,address,address,uint160,uint48)'));
    expect(T.permit2Permit).toBe(k('Permit(address,address,address,uint160,uint48,uint48)'));
  });
});

describe('monitor EVM (Ethereum + Arbitrum)', () => {
  it('primera ejecución: línea base sin alertas viejas + mensaje de "monitor activo"', async () => {
    const w = world();
    const kv = new MemKV();
    const r = await runMonitor(env(kv), fakeFetch(w), 1);
    expect(r.baseline).toBe(true);
    expect(w.getLogsCalls).toEqual([]);
    expect(w.telegram).toHaveLength(1);
    expect(w.telegram[0]).toMatch(/Monitor activo: vigilando 1 dirección\(es\) en Ethereum, Arbitrum/);
  });

  it('detecta drainer: aprobación ilimitada, setApprovalForAll, Permit2 y salida de tokens sin tx propia', async () => {
    const w = world();
    const kv = new MemKV();
    await runMonitor(env(kv), fakeFetch(w), 1);
    w.block.eth = 1050;
    w.logs.eth = [
      log(1010, USDC, [T.approval, pad(ME), pad(DRAINER)], u256(MAX), '0x01'),
      log(1011, USDC, [T.approval, pad(ME), pad(UR)], u256(5_000_000n), '0x02'),
      log(1012, BAYC, [T.approvalForAll, pad(ME), pad(DRAINER)], u256(1n), '0x03'),
      log(1013, '0x000000000022d473030f116ddee9f6b43ac78ba3', [T.permit2Permit, pad(ME), pad(USDC), pad(DRAINER)], u256((1n << 160n) - 1n) + '0'.repeat(128), '0x04'),
      log(1014, USDC, [T.transfer, pad(ME), pad(DRAINER)], u256(2_500_000_000n), '0x05'),
      log(1015, '0x' + '99'.repeat(20), [T.transfer, pad(ME), pad('0x' + '77'.repeat(20))], u256(0n), '0x06'),
      log(1016, USDC, [T.transfer, pad(DRAINER), pad(ME)], u256(1n), '0x07'), // entrante: se ignora
    ];
    const r = await runMonitor(env(kv), fakeFetch(w), 2);
    const msg = w.telegram.at(-1)!;
    expect(r.errors).toEqual([]);
    expect(msg).toMatch(/RIESGO ALTO/);
    expect(msg).toMatch(/0xd4a1…dead puede mover ILIMITADO de USDC/);
    expect(msg).toMatch(/Uniswap Universal Router v2/);
    expect(msg).toMatch(/Acceso TOTAL \(setApprovalForAll\)/);
    expect(msg).toMatch(/Permiso de Permit2 \(por firma\)/);
    expect(msg).toMatch(/Salieron 2\.500 USDC hacia 0xd4a1…dead SIN una transacción tuya/);
    expect(msg).toMatch(/address poisoning/);
    expect(msg).not.toMatch(/Salieron 0,0000/);
    expect(msg).toContain('https://revoke.cash/address/0x1111111111111111111111111111111111111111?chainId=1');
    expect(msg).toContain('https://etherscan.io/tx/0x05');
  });

  it('transacciones firmadas con tu cuenta (incluye ETH nativo) y envíos propios', async () => {
    const w = world();
    const kv = new MemKV();
    await runMonitor(env(kv), fakeFetch(w), 1);
    w.nonce.arb = 4;
    w.block.arb = 50_100;
    w.logs.arb = [log(49_990, USDC, [T.transfer, pad(ME), pad(DRAINER)], u256(10n ** 6n))];
    await runMonitor(env(kv), fakeFetch(w), 2);
    const msg = w.telegram.at(-1)!;
    expect(msg).toMatch(/Se firmaron 2 transacción\(es\) con tu cuenta/);
    expect(msg).toContain('chainId=42161');
  });

  it('recorre en tramos (límite de los RPC) y respeta las confirmaciones', async () => {
    const w = world();
    const kv = new MemKV();
    await runMonitor(env(kv), fakeFetch(w), 1);
    w.block.arb = 54_500;
    w.getLogsCalls = [];
    await runMonitor(env(kv), fakeFetch(w), 2);
    const arb = w.getLogsCalls.filter((c) => c.host === 'arb');
    expect(arb[0]!.from).toBe(50_000 - 20 + 1);
    expect(arb.at(-1)!.to).toBe(54_500 - 20);
    expect(arb.every((c) => c.to - c.from + 1 <= 2000)).toBe(true);
  });

  it('RPC caído: no avanza, avisa una sola vez a las 3 fallas', async () => {
    const w = world();
    const kv = new MemKV();
    await runMonitor(env(kv), fakeFetch(w), 1);
    w.rpcDown.add('eth');
    for (let i = 0; i < 4; i++) await runMonitor(env(kv), fakeFetch(w), 2 + i);
    const warnings = w.telegram.filter((m) => /No pude revisar Ethereum/.test(m));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toContain('SECRET');
    w.rpcDown.clear();
    w.block.eth = 1020;
    w.logs.eth = [log(1000, USDC, [T.approval, pad(ME), pad(DRAINER)], u256(MAX))];
    await runMonitor(env(kv), fakeFetch(w), 10);
    expect(w.telegram.at(-1)).toMatch(/ILIMITADO de USDC/); // no se perdieron los bloques pendientes
  });

  it('si Telegram falla, las alertas quedan pendientes y se envían en la próxima ejecución', async () => {
    const w = world();
    const kv = new MemKV();
    await runMonitor(env(kv), fakeFetch(w), 1);
    w.telegramDown = true;
    w.block.eth = 1020;
    w.logs.eth = [log(1010, USDC, [T.approval, pad(ME), pad(DRAINER)], u256(MAX))];
    const r = await runMonitor(env(kv), fakeFetch(w), 2);
    expect(r.errors.join()).toMatch(/Telegram respondió 500/);
    expect(r.errors.join()).not.toContain('SECRET');
    w.telegramDown = false;
    await runMonitor(env(kv), fakeFetch(w), 3);
    expect(w.telegram.at(-1)).toMatch(/ILIMITADO de USDC/);
  });

  it('NOTIFY_LEVEL=alta filtra lo menos grave', async () => {
    const w = world();
    const kv = new MemKV();
    await runMonitor(env(kv, { NOTIFY_LEVEL: 'alta' }), fakeFetch(w), 1);
    w.nonce.eth = 6;
    w.block.eth = 1010;
    await runMonitor(env(kv, { NOTIFY_LEVEL: 'alta' }), fakeFetch(w), 2);
    expect(w.telegram).toHaveLength(1); // solo el mensaje de inicio
  });
});

describe('monitor Solana', () => {
  const parsedTx = (...ixs: unknown[]) => ({ transaction: { message: { instructions: ixs } }, meta: { innerInstructions: [] } });
  it('línea base y luego cambios de dueño, delegación ilimitada, Assign y salidas', async () => {
    const w = world();
    const kv = new MemKV();
    w.sol.sigs = [{ signature: 'old1' }];
    await runMonitor(env(kv, { EVM_ADDRESSES: '', SOLANA_ADDRESSES: SOL_ME }), fakeFetch(w), 1);
    w.sol.sigs = [{ signature: 's4' }, { signature: 's3' }, { signature: 's2' }, { signature: 's1' }, { signature: 'old1' }];
    w.sol.txs = {
      s1: parsedTx({ program: 'spl-token', parsed: { type: 'setAuthority', info: { account: 'TokAcc111111111111111111111111111111111111', authority: SOL_ME, authorityType: 'accountOwner', newAuthority: 'Atk1111111111111111111111111111111111111111' } } }),
      s2: parsedTx({ program: 'spl-token', parsed: { type: 'approve', info: { source: 'x', delegate: 'Atk1111111111111111111111111111111111111111', owner: SOL_ME, amount: '18446744073709551615' } } }),
      s3: parsedTx({ program: 'system', parsed: { type: 'assign', info: { account: SOL_ME, owner: 'Prog111111111111111111111111111111111111111' } } }),
      s4: parsedTx(
        { program: 'system', parsed: { type: 'transfer', info: { source: SOL_ME, destination: 'Atk1111111111111111111111111111111111111111', lamports: 2_500_000_000 } } },
        { program: 'system', parsed: { type: 'transfer', info: { source: 'Otro11111111111111111111111111111111111111', destination: SOL_ME, lamports: 1 } } },
      ),
    };
    await runMonitor(env(kv, { EVM_ADDRESSES: '', SOLANA_ADDRESSES: SOL_ME }), fakeFetch(w), 2);
    const msg = w.telegram.at(-1)!;
    expect(msg).toMatch(/RIESGO ALTO/);
    expect(msg).toMatch(/Cambió la autoridad &quot;accountOwner&quot;/); // Telegram muestra &quot; como comillas
    expect(msg).toMatch(/TODO el saldo \(ilimitado\)/);
    expect(msg).toMatch(/owner change/);
    expect(msg).toMatch(/Salieron 2,5 SOL/);
    expect((msg.match(/Salieron/g) ?? []).length).toBe(1); // el entrante no cuenta
    expect(msg).toContain('https://solscan.io/tx/s1');
    // La siguiente ejecución no repite las mismas firmas.
    const before = w.telegram.length;
    await runMonitor(env(kv, { EVM_ADDRESSES: '', SOLANA_ADDRESSES: SOL_ME }), fakeFetch(w), 3);
    expect(w.telegram.length).toBe(before);
  });
});

describe('mensajes de Telegram', () => {
  it('escapa HTML y divide mensajes largos', () => {
    expect(escapeHtml('<b>&"')).toBe('&lt;b&gt;&amp;&quot;');
    const many = Array.from({ length: 200 }, (_, i) => ({ severity: 'media' as const, chain: 'Ethereum', address: `0x${String(i).padStart(40, '0')}`, text: `evento <${i}> `.repeat(5) }));
    const msgs = formatAlerts(many);
    expect(msgs.length).toBeGreaterThan(1);
    expect(msgs.every((m) => m.length <= 4096)).toBe(true);
    expect(msgs.join('')).not.toMatch(/<\d+>/);
  });
});

describe('URLs', () => {
  it('exige HTTPS salvo localhost', () => {
    expect(() => loadConfig(env(new MemKV(), { ETH_RPC_URL: 'http://rpc.evil.com' }))).toThrow(/https/);
    expect(loadConfig(env(new MemKV(), { ETH_RPC_URL: 'http://127.0.0.1:8545' })).chains[0]!.rpc).toBe('http://127.0.0.1:8545');
  });
});
