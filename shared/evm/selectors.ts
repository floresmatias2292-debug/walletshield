/**
 * Selectores de funciones (primeros 4 bytes de keccak256 de la firma).
 * Verificados en tests/unit/evm-constants.test.ts con keccak real.
 */
export const SEL = {
  approve: '0x095ea7b3', // approve(address,uint256)
  increaseAllowance: '0x39509351', // increaseAllowance(address,uint256)
  increaseApproval: '0xd73dd623', // increaseApproval(address,uint256)
  setApprovalForAll: '0xa22cb465', // setApprovalForAll(address,bool)
  transfer: '0xa9059cbb', // transfer(address,uint256)
  transferFrom: '0x23b872dd', // transferFrom(address,address,uint256)
  safeTransferFrom721: '0x42842e0e', // safeTransferFrom(address,address,uint256)
  safeTransferFrom721Data: '0xb88d4fde', // safeTransferFrom(address,address,uint256,bytes)
  safeTransferFrom1155: '0xf242432a', // safeTransferFrom(address,address,uint256,uint256,bytes)
  safeBatchTransferFrom1155: '0x2eb2c2d6', // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
  permit2612: '0xd505accf', // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
  permitDai: '0x8fcbaf0c', // permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)
  permit2Approve: '0x87517c45', // approve(address,address,uint160,uint48) en Permit2
  permit2Lockdown: '0xcc53287f', // lockdown((address,address)[]) — revoca
  multicall: '0xac9650d8', // multicall(bytes[])
  multicallDeadline: '0x5ae401dc', // multicall(uint256,bytes[])
  multicallBlockHash: '0x1f0464d1', // multicall(bytes32,bytes[])
  decimals: '0x313ce567',
  symbol: '0x95d89b41',
  name: '0x06fdde03',
  balanceOf: '0x70a08231',
} as const;

/**
 * Funciones "payable" con nombres que usan los kits de drainers para que la
 * víctima envíe ETH creyendo que reclama un premio o "actualiza seguridad".
 */
export const DRAINER_SELECTORS: Readonly<Record<string, string>> = {
  '0x3158952e': 'Claim()',
  '0x5fba79f5': 'SecurityUpdate()',
  '0x79372f9a': 'ClaimReward()',
  '0x12798972': 'ClaimRewards()',
  '0xa16f15c3': 'Connect()',
  '0xb9d2d32c': 'Execute()',
  '0x9cad7b18': 'Multicall()',
};

/** Lecturas on-chain que el analizador puede pedir a la wallet (solo lectura). */
export const READONLY_CALL_SELECTORS: ReadonlySet<string> = new Set([SEL.decimals, SEL.symbol, SEL.name, SEL.balanceOf]);
