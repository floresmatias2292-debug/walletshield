/**
 * Casos de drainers (patrones documentados públicamente: Inferno Drainer,
 * Pink Drainer, drainers de Seaport/Blur, falsos "Claim()") y flujos
 * legítimos de Uniswap, OpenSea, UniswapX, CoW, 1inch. Los payloads son
 * RECONSTRUIDOS con la misma estructura que los reales; las direcciones de
 * atacante son ficticias.
 */
import { describe, expect, it } from 'vitest';
import { analyzeRequest, lookupsFor, modalThreshold } from '../../shared/evm';
import type { AnalysisInput } from '../../shared/evm/context';
import { riskAtLeast, type RiskLevel } from '../../shared/risk';

const USER = '0x1111111111111111111111111111111111111111';
const DRAINER_EOA = '0xd4a1e2000000000000000000000000000000dead';
const DRAINER_CONTRACT = '0xc0ffee0000000000000000000000000000c0ffee';
const LISTED_BAD = '0xbadbadbadbadbadbadbadbadbadbadbadbadbad0';
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const UR_V2 = '0x66a9893cc07d91d95644aedd05d03f95e1dba8af';
const UNISWAPX_V2 = '0x00000011F84B9aa48e5f8aA8B9897600006289Be';
const SEAPORT_16 = '0x0000000000000068F116a894984e2DB1123eB395';
const OPENSEA_CONDUIT = '0x1E0049783F008A0085193E00003D00cd54003c71';
const ONEINCH_V6 = '0x111111125421cA6dc452d289314280a0f8842A65';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const DAI = '0x6B175474E89094C44Da98b954EedeAC495271d0F';
const BAYC = '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D';
const MAX256 = (1n << 256n) - 1n;
const MAX160 = (1n << 160n) - 1n;
const NOW = Date.parse('2026-11-09T12:00:00Z');
const NOW_S = Math.floor(NOW / 1000);

const w = (x: bigint | string | boolean) =>
  typeof x === 'string' ? x.replace(/^0x/, '').toLowerCase().padStart(64, '0') : (typeof x === 'boolean' ? (x ? 1n : 0n) : x).toString(16).padStart(64, '0');
const call = (sel: string, ...args: Array<bigint | string | boolean>) => sel + args.map(w).join('');

function input(answers: Record<string, unknown> = {}, over: Partial<AnalysisInput> = {}): AnalysisInput {
  return {
    chainId: 1,
    account: USER,
    pageHost: 'app.uniswap.org',
    siteRisk: 'none',
    now: NOW,
    badAddresses: new Set([LISTED_BAD]),
    answers: new Map(Object.entries(answers)),
    ...over,
  };
}
const eoa = (a: string) => ({ [`code:${a.toLowerCase()}`]: false });
const contract = (a: string) => ({ [`code:${a.toLowerCase()}`]: true });

function analyze(method: string, params: unknown[], answers: Record<string, unknown> = {}, over: Partial<AnalysisInput> = {}) {
  return analyzeRequest(method, params, input(answers, over));
}
const codes = (a: { findings: readonly { code: string }[] }) => a.findings.map((f) => f.code);
const order: Record<RiskLevel, number> = { none: 0, low: 1, medium: 2, high: 3 };
const atMost = (r: RiskLevel, max: RiskLevel) => expect(order[r], `riesgo ${r} > ${max}`).toBeLessThanOrEqual(order[max]);

const td = (domain: object, primaryType: string, message: object) =>
  JSON.stringify({ types: { EIP712Domain: [] }, domain, primaryType, message });

describe('DRAINERS → riesgo alto', () => {
  it('Inferno: PermitBatch de Permit2 sobre 4 tokens ilimitados a una cuenta personal', () => {
    const data = td({ name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 }, 'PermitBatch', {
      details: [USDC, USDT, WETH, DAI].map((token) => ({ token, amount: MAX160.toString(), expiration: '281474976710655', nonce: '0' })),
      spender: DRAINER_EOA,
      sigDeadline: String(NOW_S + 3600),
    });
    const a = analyze('eth_signTypedData_v4', [USER, data], eoa(DRAINER_EOA));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('permit-batch');
    expect(a.summary.join(' ')).toMatch(/ILIMITADO de USDC/);
    expect(a.summary.join(' ')).toMatch(/nunca/);
  });
  it('Permit2 PermitTransferFrom (retiro inmediato) a contrato desconocido', () => {
    const data = td({ name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 }, 'PermitTransferFrom', {
      permitted: { token: USDC, amount: '5000000000' }, spender: DRAINER_CONTRACT, nonce: '1', deadline: String(NOW_S + 600),
    });
    const a = analyze('eth_signTypedData_v4', [USER, data], contract(DRAINER_CONTRACT));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('permit-transfer');
  });
  it('"Permit2" falso (verifyingContract no oficial)', () => {
    const data = td({ name: 'Permit2', chainId: 1, verifyingContract: DRAINER_CONTRACT }, 'PermitSingle', {
      details: { token: USDC, amount: '1', expiration: String(NOW_S + 100), nonce: '0' }, spender: UR_V2, sigDeadline: String(NOW_S + 100),
    });
    expect(codes(analyze('eth_signTypedData_v4', [USER, data]))).toContain('fake-contract');
  });
  it('EIP-2612 Permit ilimitado y sin vencimiento a contrato desconocido', () => {
    const data = td({ name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC }, 'Permit', {
      owner: USER, spender: DRAINER_CONTRACT, value: MAX256.toString(), nonce: '0', deadline: MAX256.toString(),
    });
    const a = analyze('eth_signTypedData_v4', [USER, data], contract(DRAINER_CONTRACT));
    expect(a.risk).toBe('high');
    expect(codes(a)).toEqual(expect.arrayContaining(['permit', 'long-expiry']));
  });
  it('DAI permit (allowed=true) a cuenta personal', () => {
    const data = td({ name: 'Dai Stablecoin', version: '1', chainId: 1, verifyingContract: DAI }, 'Permit', {
      holder: USER, spender: DRAINER_EOA, nonce: '0', expiry: '0', allowed: true,
    });
    expect(analyze('eth_signTypedData_v4', [USER, data], eoa(DRAINER_EOA)).risk).toBe('high');
  });
  it('Seaport: tus NFTs a la venta por 0 (todo para el atacante)', () => {
    const data = td({ name: 'Seaport', version: '1.6', chainId: 1, verifyingContract: SEAPORT_16 }, 'OrderComponents', {
      offerer: USER, zone: '0x0000000000000000000000000000000000000000',
      offer: [{ itemType: 2, token: BAYC, identifierOrCriteria: '1234', startAmount: '1', endAmount: '1' }],
      consideration: [
        { itemType: 0, token: '0x0000000000000000000000000000000000000000', identifierOrCriteria: '0', startAmount: '1', endAmount: '1', recipient: DRAINER_EOA },
      ],
      orderType: 0, startTime: String(NOW_S), endTime: String(NOW_S + 86400 * 365), zoneHash: '0x' + '0'.repeat(64), salt: '1', conduitKey: '0x' + '0'.repeat(64), counter: '0',
    });
    const a = analyze('eth_signTypedData_v4', [USER, data]);
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('nft-sale-zero');
  });
  it('Seaport con contrato falso', () => {
    const data = td({ name: 'Seaport', chainId: 1, verifyingContract: DRAINER_CONTRACT }, 'OrderComponents', { offerer: USER, offer: [], consideration: [] });
    expect(analyze('eth_signTypedData_v4', [USER, data]).risk).toBe('high');
  });
  it('Blur bulk "Root" (firma ciega de órdenes)', () => {
    const data = td({ name: 'Blur Exchange', version: '1.0', chainId: 1, verifyingContract: '0x000000000000Ad05Ccc4F10045630fb830B95127' }, 'Root', { root: '0x' + 'ab'.repeat(32) });
    const a = analyze('eth_signTypedData_v4', [USER, data]);
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('blur-bulk');
  });
  it('approve ilimitado a cuenta personal', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0x095ea7b3', DRAINER_EOA, MAX256) }], eoa(DRAINER_EOA));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('unlimited-approval');
  });
  it('increaseAllowance ilimitado a contrato desconocido', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: USDT, data: call('0x39509351', DRAINER_CONTRACT, MAX256) }], contract(DRAINER_CONTRACT));
    expect(a.risk).toBe('high');
  });
  it('setApprovalForAll a cuenta personal (Pink Drainer)', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: BAYC, data: call('0xa22cb465', DRAINER_EOA, true) }], eoa(DRAINER_EOA));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('approval-for-all');
  });
  it('falso "Claim()" que envía casi todo el ETH', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: DRAINER_CONTRACT, value: '0x' + (99n * 10n ** 16n).toString(16), data: '0x3158952e' }], {
      ...contract(DRAINER_CONTRACT), [`balance:${USER}`]: 10n ** 18n,
    });
    expect(a.risk).toBe('high');
    expect(codes(a)).toEqual(expect.arrayContaining(['drainer-function', 'native-drain']));
  });
  it('"SecurityUpdate()" con poco ETH igual es alto', () => {
    expect(analyze('eth_sendTransaction', [{ from: USER, to: DRAINER_CONTRACT, value: '0x1', data: '0x5fba79f5' }], contract(DRAINER_CONTRACT)).risk).toBe('high');
  });
  it('multicall que esconde un approve ilimitado', () => {
    const inner = call('0x095ea7b3', DRAINER_EOA, MAX256).slice(2);
    const len = inner.length / 2;
    const data = '0xac9650d8' + w(32n) + w(1n) + w(32n) + w(BigInt(len)) + inner.padEnd(Math.ceil(inner.length / 64) * 64, '0');
    const a = analyze('eth_sendTransaction', [{ from: USER, to: USDC, data }], eoa(DRAINER_EOA));
    expect(a.risk).toBe('high');
  });
  it('wallet_sendCalls: approve + transferFrom en lote', () => {
    const a = analyze('wallet_sendCalls', [{ from: USER, chainId: '0x1', calls: [
      { to: USDC, data: call('0x095ea7b3', DRAINER_CONTRACT, MAX256) },
      { to: DRAINER_CONTRACT, data: '0x12345678' },
    ] }], contract(DRAINER_CONTRACT));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('batch-calls');
  });
  it('EIP-7702: delegar la cuenta', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: USER, authorizationList: [{ address: DRAINER_CONTRACT, chainId: '0x1', nonce: '0x0' }] }]);
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('eip7702');
  });
  it('transferencia a dirección en lista negra', () => {
    expect(analyze('eth_sendTransaction', [{ from: USER, to: LISTED_BAD, value: '0x10' }]).risk).toBe('high');
  });
  it('eth_sign → alto y bloqueo duro en modo estricto', () => {
    const a = analyze('eth_sign', [USER, '0x' + 'ab'.repeat(32)]);
    expect(a.risk).toBe('high');
    expect(a.hardBlockInStrict).toBe(true);
  });
  it('personal_sign de un hash de 32 bytes (firma ciega)', () => {
    expect(codes(analyze('personal_sign', ['0x' + '7f'.repeat(32), USER]))).toContain('blind-hash');
  });
  it('SIWE para otro dominio (robo de sesión)', () => {
    const msg = 'app.uniswap.org wants you to sign in with your Ethereum account:\n' + USER + '\n\nSign in\n\nURI: https://app.uniswap.org\nVersion: 1\nChain ID: 1\nNonce: abc12345\nIssued At: 2026-11-09T12:00:00Z';
    const a = analyze('personal_sign', [msg, USER], {}, { pageHost: 'uniswap-claim.xyz' });
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('siwe-mismatch');
  });
  it('sitio sospechoso + permiso limitado → alto', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0x095ea7b3', ONEINCH_V6, 10n ** 6n) }], {}, { siteRisk: 'medium', pageHost: 'uniswap-app.xyz' });
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('suspicious-site');
  });
});

describe('LEGÍTIMOS → sin falsos positivos', () => {
  it('Uniswap: PermitSingle a Universal Router (monto ilimitado de Permit2, vence en 30 días)', () => {
    const data = td({ name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 }, 'PermitSingle', {
      details: { token: USDC, amount: MAX160.toString(), expiration: String(NOW_S + 30 * 86400), nonce: '3' },
      spender: UR_V2, sigDeadline: String(NOW_S + 1800),
    });
    const a = analyze('eth_signTypedData_v4', [USER, data]);
    atMost(a.risk, 'low');
    expect(riskAtLeast(a.risk, modalThreshold('normal'))).toBe(false);
  });
  it('Uniswap: execute del Universal Router con ETH', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: UR_V2, value: '0x16345785d8a0000', data: '0x3593564c' + w(96n) + w(160n) + w(BigInt(NOW_S + 600)) + w(1n) + '0b' + '0'.repeat(62) + w(0n) }], {
      [`balance:${USER}`]: 10n ** 19n,
    });
    expect(a.risk).toBe('none');
  });
  it('Uniswap: approve exacto a Permit2 → sin riesgo; ilimitado → advertencia media (contrato oficial)', () => {
    expect(analyze('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0x095ea7b3', PERMIT2, 25n * 10n ** 6n) }]).risk).toBe('none');
    const a = analyze('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0x095ea7b3', PERMIT2, MAX256) }]);
    expect(a.risk).toBe('medium');
    expect(a.findings[0]!.text).toMatch(/oficial conocido/);
  });
  it('revocar (approve 0) → sin riesgo', () => {
    expect(analyze('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0x095ea7b3', DRAINER_EOA, 0n) }]).risk).toBe('none');
  });
  it('UniswapX: PermitWitnessTransferFrom al reactor oficial', () => {
    const data = td({ name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 }, 'PermitWitnessTransferFrom', {
      permitted: { token: USDC, amount: '1000000000' }, spender: UNISWAPX_V2, nonce: '99', deadline: String(NOW_S + 120), witness: { info: {} },
    });
    atMost(analyze('eth_signTypedData_v4', [USER, data]).risk, 'low');
  });
  it('OpenSea: listing normal (0,975 ETH a ti + comisión)', () => {
    const data = td({ name: 'Seaport', version: '1.6', chainId: 1, verifyingContract: SEAPORT_16 }, 'OrderComponents', {
      offerer: USER,
      offer: [{ itemType: 2, token: BAYC, identifierOrCriteria: '1234', startAmount: '1', endAmount: '1' }],
      consideration: [
        { itemType: 0, token: '0x0000000000000000000000000000000000000000', identifierOrCriteria: '0', startAmount: '975000000000000000', endAmount: '975000000000000000', recipient: USER },
        { itemType: 0, token: '0x0000000000000000000000000000000000000000', identifierOrCriteria: '0', startAmount: '25000000000000000', endAmount: '25000000000000000', recipient: '0x0000a26b00c1F0DF003000390027140000fAa719' },
      ],
      startTime: String(NOW_S), endTime: String(NOW_S + 86400 * 30), counter: '0',
    });
    const a = analyze('eth_signTypedData_v4', [USER, data]);
    expect(a.risk).toBe('low');
    expect(a.summary.join(' ')).toMatch(/Recibes: 0,975 ETH/);
  });
  it('OpenSea: setApprovalForAll al Conduit oficial → medio (advertencia, no alto)', () => {
    expect(analyze('eth_sendTransaction', [{ from: USER, to: BAYC, data: call('0xa22cb465', OPENSEA_CONDUIT, true) }]).risk).toBe('medium');
  });
  it('Blur: orden de venta con precio', () => {
    const data = td({ name: 'Blur Exchange', chainId: 1, verifyingContract: '0x000000000000Ad05Ccc4F10045630fb830B95127' }, 'Order', {
      trader: USER, side: 1, collection: BAYC, tokenId: '1', amount: '1', paymentToken: '0x0000000000000000000000000000000000000000', price: '30000000000000000000',
    });
    expect(analyze('eth_signTypedData_v4', [USER, data]).risk).toBe('low');
  });
  it('CoW Swap: orden GPv2 (firma genérica sin permisos)', () => {
    const data = td({ name: 'Gnosis Protocol', version: 'v2', chainId: 1, verifyingContract: '0x9008D19f58AAbD9eD0D60971565AA8510560ab41' }, 'Order', {
      sellToken: WETH, buyToken: USDC, receiver: '0x0000000000000000000000000000000000000000', sellAmount: '1000000000000000000', buyAmount: '3000000000',
      validTo: NOW_S + 600, appData: '0x' + '0'.repeat(64), feeAmount: '0', kind: 'sell', partiallyFillable: false, sellTokenBalance: 'erc20', buyTokenBalance: 'erc20',
    });
    expect(analyze('eth_signTypedData_v4', [USER, data]).risk).toBe('low');
  });
  it('1inch: permit limitado al router oficial', () => {
    const data = td({ name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC }, 'Permit', {
      owner: USER, spender: ONEINCH_V6, value: '100000000', nonce: '0', deadline: String(NOW_S + 1200),
    });
    atMost(analyze('eth_signTypedData_v4', [USER, data]).risk, 'low');
  });
  it('envío pequeño de ETH a un amigo', () => {
    expect(analyze('eth_sendTransaction', [{ from: USER, to: DRAINER_EOA, value: '0x2386f26fc10000' }], { ...eoa(DRAINER_EOA), [`balance:${USER}`]: 10n ** 18n }).risk).toBe('none');
  });
  it('SIWE del mismo sitio y mensaje de login de OpenSea', () => {
    const siwe = 'opensea.io wants you to sign in with your Ethereum account:\n' + USER + '\n\nClick to sign in.\n\nURI: https://opensea.io/\nVersion: 1\nChain ID: 1\nNonce: x9a8b7c6\nIssued At: 2026-11-09T12:00:00Z';
    expect(analyze('personal_sign', [siwe, USER], {}, { pageHost: 'opensea.io' }).risk).toBe('none');
    const hex = '0x' + Buffer.from('Welcome to OpenSea!\n\nClick to sign in and accept the OpenSea Terms of Service.\n\nWallet address:\n' + USER).toString('hex');
    expect(analyze('personal_sign', [hex, USER]).risk).toBe('low');
  });
});

describe('detalles del analizador', () => {
  it('transferir todo el saldo de un token a una cuenta personal → medio', () => {
    const a = analyze('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0xa9059cbb', DRAINER_EOA, 500n * 10n ** 6n) }], {
      ...eoa(DRAINER_EOA), [`tokenBalance:${USDC.toLowerCase()}:${USER}`]: 500n * 10n ** 6n,
    });
    expect(a.risk).toBe('medium');
    expect(a.summary[0]).toMatch(/500 USDC/);
  });
  it('calldata malformada → medio, nunca silencio', () => {
    expect(codes(analyze('eth_sendTransaction', [{ from: USER, to: USDC, data: '0x095ea7b3' + '00'.repeat(10) }]))).toContain('undecodable');
  });
  it('red distinta en la firma → medio', () => {
    const data = td({ name: 'App', chainId: 42161 }, 'Login', { nonce: '1' });
    expect(codes(analyze('eth_signTypedData_v4', [USER, data]))).toContain('chain-mismatch');
  });
  it('parámetros de typed data invertidos o inválidos', () => {
    const data = td({ name: 'Blur Exchange' }, 'Root', { root: '0x00' });
    expect(analyze('eth_signTypedData_v4', [data, USER]).risk).toBe('high');
    expect(analyze('eth_signTypedData_v4', [USER, '{no json']).risk).toBe('high');
  });
  it('lookupsFor pide solo lo necesario', () => {
    const l = lookupsFor('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0x095ea7b3', DRAINER_EOA, MAX256) }], input());
    expect(l).toEqual([{ kind: 'code', address: DRAINER_EOA }]);
    expect(lookupsFor('eth_sendTransaction', [{ from: USER, to: USDC, data: call('0x095ea7b3', PERMIT2, MAX256) }], input())).toEqual([]);
  });
  it('analiza en menos de 1 ms en promedio (objetivo: < 5 ms)', () => {
    const data = td({ name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 }, 'PermitBatch', {
      details: [USDC, USDT, WETH, DAI].map((token) => ({ token, amount: MAX160.toString(), expiration: '281474976710655', nonce: '0' })),
      spender: DRAINER_EOA, sigDeadline: String(NOW_S + 3600),
    });
    const inp = input(eoa(DRAINER_EOA));
    const t0 = performance.now();
    for (let i = 0; i < 300; i++) analyzeRequest('eth_signTypedData_v4', [USER, data], inp);
    expect((performance.now() - t0) / 300).toBeLessThan(1);
  });
});
