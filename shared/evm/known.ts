/**
 * Contratos legítimos conocidos (Ethereum y Arbitrum).
 *
 * `src: 'doc'`: dirección copiada de la documentación oficial del proyecto
 * en GitHub (verificada el 2026-11-09). `src: 'eip55'`: dirección conocida
 * verificada solo por su checksum EIP-55 (tests/unit/evm-constants.test.ts),
 * que detecta errores de tipeo con probabilidad > 99,9 %.
 *
 * Que un contrato sea "conocido" baja el riesgo pero NUNCA lo anula: una
 * aprobación ilimitada sigue mostrando advertencia.
 */
export type ChainId = 1 | 42161;
export const ANY_CHAIN = 0;

export interface KnownContract {
  readonly address: string;
  readonly label: string;
  readonly chains: readonly number[]; // [0] = todas las cadenas EVM (misma dirección)
  readonly kind: 'spender' | 'marketplace' | 'token' | 'bridge' | 'protocol';
  readonly src: 'doc' | 'eip55';
}

export const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';

const K = (
  address: string,
  label: string,
  chains: readonly number[],
  kind: KnownContract['kind'],
  src: KnownContract['src'],
): KnownContract => ({ address, label, chains, kind, src });

export const KNOWN_CONTRACTS: readonly KnownContract[] = [
  K('0x000000000022D473030F116dDEE9F6B43aC78BA3', 'Permit2 (Uniswap)', [ANY_CHAIN], 'spender', 'doc'),
  // Uniswap Universal Router — deploy-addresses/{mainnet,arbitrum}.json
  K('0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B', 'Uniswap Universal Router v1', [1], 'spender', 'doc'),
  K('0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD', 'Uniswap Universal Router v1.2', [1], 'spender', 'doc'),
  K('0x66a9893cc07d91d95644aedd05d03f95e1dba8af', 'Uniswap Universal Router v2', [1], 'spender', 'doc'),
  K('0x4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA', 'Uniswap Universal Router v2.1.1', [1], 'spender', 'doc'),
  K('0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85', 'Uniswap Universal Router v2.1.2', [1], 'spender', 'doc'),
  K('0x4C60051384bd2d3C01bfc845Cf5F4b44bcbE9de5', 'Uniswap Universal Router v1', [42161], 'spender', 'doc'),
  K('0xeC8B0F7Ffe3ae75d7FfAb09429e3675bb63503e4', 'Uniswap Universal Router v1.2', [42161], 'spender', 'doc'),
  K('0x5E325eDA8064b456f4781070C0738d849c824258', 'Uniswap Universal Router v1.2', [42161], 'spender', 'doc'),
  K('0xa51afafe0263b40edaef0df8781ea9aa03e381a3', 'Uniswap Universal Router v2', [42161], 'spender', 'doc'),
  K('0x8B844f885672f333Bc0042cB669255f93a4C1E6b', 'Uniswap Universal Router v2.1.1', [42161], 'spender', 'doc'),
  K('0x2d01411773c8C24805306E89A41F7855C3c4Fe65', 'Uniswap Universal Router v2.1.2', [42161], 'spender', 'doc'),
  // UniswapX — README
  K('0x00000011F84B9aa48e5f8aA8B9897600006289Be', 'UniswapX V2 Dutch Order Reactor', [1], 'spender', 'doc'),
  K('0x0000000015757c461808EA25Eb309638B62681cf', 'UniswapX V3 Dutch Order Reactor', [1], 'spender', 'doc'),
  K('0x6000da47483062A0D734Ba3dc7576Ce6A0B645C4', 'UniswapX Exclusive Dutch Order Reactor', [1], 'spender', 'doc'),
  K('0xB274d5F4b833b61B340b654d600A864fB604a87c', 'UniswapX V3 Dutch Order Reactor', [42161], 'spender', 'doc'),
  // Uniswap v2/v3 clásicos
  K('0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D', 'Uniswap V2 Router', [1], 'spender', 'eip55'),
  K('0xE592427A0AEce92De3Edee1F18E0157C05861564', 'Uniswap V3 SwapRouter', [ANY_CHAIN], 'spender', 'eip55'),
  K('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', 'Uniswap V3 SwapRouter02', [ANY_CHAIN], 'spender', 'eip55'),
  K('0xC36442b4a4522E871399CD717aBDD847Ab11FE88', 'Uniswap V3 Positions NFT', [ANY_CHAIN], 'spender', 'eip55'),
  // Seaport (OpenSea) — README de ProjectOpenSea/seaport
  K('0x00000000006c3852cbEf3e08E8dF289169EdE581', 'Seaport 1.1', [ANY_CHAIN], 'marketplace', 'doc'),
  K('0x00000000000006c7676171937C444f6BDe3D6282', 'Seaport 1.2', [ANY_CHAIN], 'marketplace', 'doc'),
  K('0x0000000000000aD24e80fd803C6ac37206a45f15', 'Seaport 1.3', [ANY_CHAIN], 'marketplace', 'doc'),
  K('0x00000000000001ad428e4906aE43D8F9852d0dD6', 'Seaport 1.4', [ANY_CHAIN], 'marketplace', 'doc'),
  K('0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC', 'Seaport 1.5', [ANY_CHAIN], 'marketplace', 'doc'),
  K('0x0000000000000068F116a894984e2DB1123eB395', 'Seaport 1.6', [ANY_CHAIN], 'marketplace', 'doc'),
  K('0x00000000F9490004C11Cef243f5400493c00Ad63', 'Seaport ConduitController', [ANY_CHAIN], 'marketplace', 'doc'),
  K('0x1E0049783F008A0085193E00003D00cd54003c71', 'OpenSea Conduit', [ANY_CHAIN], 'marketplace', 'eip55'),
  // Blur
  K('0x000000000000Ad05Ccc4F10045630fb830B95127', 'Blur Exchange', [1], 'marketplace', 'eip55'),
  K('0x00000000000111AbE46ff893f3B2fdF1F759a8A8', 'Blur Execution Delegate', [1], 'marketplace', 'eip55'),
  K('0x29469395eAf6f95920E59F858042f0e28D98a20B', 'Blur Blend', [1], 'marketplace', 'eip55'),
  K('0xb2ecfE4E4D61f8790bbb9DE2D1259B9e2410CEA5', 'Blur Marketplace', [1], 'marketplace', 'eip55'),
  // CoW Protocol — networks.json
  K('0x9008D19f58AAbD9eD0D60971565AA8510560ab41', 'CoW Protocol Settlement', [1, 42161], 'spender', 'doc'),
  K('0xC92E8bdf79f0507f65a392b0ab4667716BFE0110', 'CoW Protocol Vault Relayer', [1, 42161], 'spender', 'doc'),
  // Agregadores
  K('0x1111111254EEB25477B68fb85Ed929f73A960582', '1inch Router v5', [ANY_CHAIN], 'spender', 'eip55'),
  K('0x111111125421cA6dc452d289314280a0f8842A65', '1inch Router v6', [ANY_CHAIN], 'spender', 'eip55'),
  K('0xDef1C0ded9bec7F1a1670819833240f027b25EfF', '0x Exchange Proxy', [1, 42161], 'spender', 'eip55'),
  K('0x0000000000001fF3684f28c67538d4D072C22734', '0x AllowanceHolder', [ANY_CHAIN], 'spender', 'eip55'),
  K('0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57', 'ParaSwap Augustus v5', [ANY_CHAIN], 'spender', 'eip55'),
  K('0x216B4B4Ba9F3e719726886d34a177484278Bfcae', 'ParaSwap TokenTransferProxy', [ANY_CHAIN], 'spender', 'eip55'),
  K('0x6A000F20005980200259B80c5102003040001068', 'ParaSwap Augustus v6.2', [ANY_CHAIN], 'spender', 'eip55'),
  K('0xCf5540fFFCdC3d510B18bFcA6d2b9987b0772559', 'Odos Router v2', [1], 'spender', 'eip55'),
  K('0xa669e7A0d4b3e4Fa48af2dE86BD4CD7126Be4e13', 'Odos Router v2', [42161], 'spender', 'eip55'),
  K('0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE', 'LI.FI Diamond', [ANY_CHAIN], 'bridge', 'eip55'),
  // Protocolos
  K('0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2', 'Aave V3 Pool', [1], 'protocol', 'eip55'),
  K('0x794a61358D6845594F94dc1DB02A252b5b4814aD', 'Aave V3 Pool', [42161], 'protocol', 'eip55'),
  K('0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1', 'Lido Withdrawal Queue', [1], 'protocol', 'eip55'),
  K('0xc873fEcbd354f5A56E00E710B90EF4201db2448d', 'Camelot Router', [42161], 'spender', 'eip55'),
  K('0xaBBc5F99639c9B6bCb58544ddf04EFA6802F4064', 'GMX Router', [42161], 'spender', 'eip55'),
  // Puentes
  K('0x72Ce9c846789fdB6fC1f34aC4AD25Dd9ef7031ef', 'Arbitrum L1 Gateway Router', [1], 'bridge', 'eip55'),
  K('0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f', 'Arbitrum Delayed Inbox', [1], 'bridge', 'eip55'),
  K('0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5', 'Across SpokePool', [1], 'bridge', 'eip55'),
  K('0xe35e9842fceaCA96570B734083f4a58e8F7C5f2A', 'Across SpokePool', [42161], 'bridge', 'eip55'),
  // Tokens (para mostrar símbolo y decimales sin consultar la cadena)
  K('0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', 'WETH', [1], 'token', 'eip55'),
  K('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'USDC', [1], 'token', 'eip55'),
  K('0xdAC17F958D2ee523a2206206994597C13D831ec7', 'USDT', [1], 'token', 'eip55'),
  K('0x6B175474E89094C44Da98b954EedeAC495271d0F', 'DAI', [1], 'token', 'eip55'),
  K('0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599', 'WBTC', [1], 'token', 'eip55'),
  K('0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84', 'stETH', [1], 'token', 'eip55'),
  K('0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0', 'wstETH', [1], 'token', 'eip55'),
  K('0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', 'WETH', [42161], 'token', 'eip55'),
  K('0xaf88d065e77c8cC2239327C5EDb3A432268e5831', 'USDC', [42161], 'token', 'eip55'),
  K('0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', 'USDT', [42161], 'token', 'eip55'),
  K('0x912CE59144191C1204E64559FE8253a0e49E6548', 'ARB', [42161], 'token', 'eip55'),
];

export const TOKEN_DECIMALS: Readonly<Record<string, number>> = {
  WETH: 18, USDC: 6, USDT: 6, DAI: 18, WBTC: 8, stETH: 18, wstETH: 18, ARB: 18,
};

const INDEX = new Map<string, KnownContract[]>();
for (const k of KNOWN_CONTRACTS) {
  const a = k.address.toLowerCase();
  INDEX.set(a, [...(INDEX.get(a) ?? []), k]);
}

/** Contrato conocido en esa cadena (o en cualquier cadena si chainId es null). */
export function knownContract(address: string, chainId: number | null): KnownContract | null {
  const list = INDEX.get(address.toLowerCase());
  if (!list) return null;
  for (const k of list) {
    if (chainId === null || k.chains.includes(ANY_CHAIN) || k.chains.includes(chainId)) return k;
  }
  return null;
}

export function isWethLike(address: string, chainId: number | null): boolean {
  return knownContract(address, chainId)?.label === 'WETH';
}
