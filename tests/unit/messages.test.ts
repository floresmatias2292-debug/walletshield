import { describe, expect, it } from 'vitest';
import { isExtensionPageSender, parsePrivilegedRequest } from '../../shared/messages';
import { DEFAULT_SETTINGS, parseSettings } from '../../shared/settings';

const ID = 'abcdefghijklmnopabcdefghijklmnop';

describe('validación de mensajes', () => {
  it('acepta solo tipos conocidos con forma correcta', () => {
    expect(parsePrivilegedRequest({ type: 'state:get' })).toEqual({ type: 'state:get' });
    expect(parsePrivilegedRequest({ type: 'blocked:proceed', host: 'a.com' })).toEqual({ type: 'blocked:proceed', host: 'a.com' });
    expect(parsePrivilegedRequest({ type: 'blocked:proceed', host: 7 })).toBeNull();
    expect(parsePrivilegedRequest({ type: 'blocked:proceed', host: 'a'.repeat(300) })).toBeNull();
    expect(parsePrivilegedRequest({ type: 'eval', code: '1' })).toBeNull();
    expect(parsePrivilegedRequest('state:get')).toBeNull();
  });
  it('distingue páginas de la extensión de content scripts y otras extensiones', () => {
    expect(isExtensionPageSender({ id: ID, origin: `chrome-extension://${ID}` }, ID)).toBe(true);
    expect(isExtensionPageSender({ id: ID, origin: 'https://evil.com' }, ID)).toBe(false); // content script
    expect(isExtensionPageSender({ id: 'otra', origin: 'chrome-extension://otra' }, ID)).toBe(false);
    expect(isExtensionPageSender({ id: ID, url: `chrome-extension://${ID}/blocked/blocked.html` }, ID)).toBe(true);
  });
});

describe('ajustes', () => {
  it('valida e ignora basura en importaciones', () => {
    const s = parseSettings({ strictness: 'paranoid', sources: { metamask: 'yes' }, allowlist: ['App.Uniswap.org', 5, '<script>', 'app.uniswap.org'], rdapLookup: 1 });
    expect(s.strictness).toBe('normal');
    expect(s.sources.metamask).toBe(true);
    expect(s.allowlist).toEqual(['app.uniswap.org']);
    expect(s.rdapLookup).toBe(false);
    expect(parseSettings(null)).toEqual(DEFAULT_SETTINGS);
  });
});
