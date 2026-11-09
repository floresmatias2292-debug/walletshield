import { describe, expect, it } from 'vitest';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { DRAINER_SELECTORS, SEL } from '../../shared/evm/selectors';
import { KNOWN_CONTRACTS, PERMIT2 } from '../../shared/evm/known';

const enc = new TextEncoder();
const selector = (sig: string) => `0x${Buffer.from(keccak_256(enc.encode(sig))).toString('hex').slice(0, 8)}`;
function checksum(a: string): string {
  const l = a.slice(2).toLowerCase();
  const h = Buffer.from(keccak_256(enc.encode(l))).toString('hex');
  return `0x${[...l].map((c, i) => (parseInt(h[i]!, 16) >= 8 ? c.toUpperCase() : c)).join('')}`;
}

describe('constantes EVM verificadas con keccak256', () => {
  const sigs: Record<keyof typeof SEL, string> = {
    approve: 'approve(address,uint256)',
    increaseAllowance: 'increaseAllowance(address,uint256)',
    increaseApproval: 'increaseApproval(address,uint256)',
    setApprovalForAll: 'setApprovalForAll(address,bool)',
    transfer: 'transfer(address,uint256)',
    transferFrom: 'transferFrom(address,address,uint256)',
    safeTransferFrom721: 'safeTransferFrom(address,address,uint256)',
    safeTransferFrom721Data: 'safeTransferFrom(address,address,uint256,bytes)',
    safeTransferFrom1155: 'safeTransferFrom(address,address,uint256,uint256,bytes)',
    safeBatchTransferFrom1155: 'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)',
    permit2612: 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)',
    permitDai: 'permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)',
    permit2Approve: 'approve(address,address,uint160,uint48)',
    permit2Lockdown: 'lockdown((address,address)[])',
    multicall: 'multicall(bytes[])',
    multicallDeadline: 'multicall(uint256,bytes[])',
    multicallBlockHash: 'multicall(bytes32,bytes[])',
    decimals: 'decimals()',
    symbol: 'symbol()',
    name: 'name()',
    balanceOf: 'balanceOf(address)',
  };
  for (const [k, sig] of Object.entries(sigs)) {
    it(`${k} = ${sig}`, () => expect(SEL[k as keyof typeof SEL]).toBe(selector(sig)));
  }
  it('selectores de funciones de drainers', () => {
    for (const [sel, sig] of Object.entries(DRAINER_SELECTORS)) expect(sel).toBe(selector(sig));
  });
  it('todas las direcciones conocidas tienen checksum EIP-55 válido (o vienen en minúsculas de la doc oficial)', () => {
    for (const k of KNOWN_CONTRACTS) {
      if (k.address === k.address.toLowerCase()) expect(k.src).toBe('doc');
      else expect(checksum(k.address), `${k.label}`).toBe(k.address);
    }
  });
  it('Permit2 canónico', () => expect(PERMIT2).toBe('0x000000000022d473030f116ddee9f6b43ac78ba3'));
});
