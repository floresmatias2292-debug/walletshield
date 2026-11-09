/**
 * Dominios legítimos de alto valor para atacantes. Se usan para:
 *  1. detectar imitaciones (homoglifos, typosquatting, combos "marca-claim"),
 *  2. no bloquear nunca estos dominios aunque una lista pública los incluya
 *     por error (protección contra falsos positivos).
 *
 * `generic: true` marca etiquetas que son palabras comunes (safe, blur, curve…):
 * para ellas solo se comparan dominios completos, no la etiqueta suelta,
 * porque "blur.com" o "safe.com" son sitios distintos y legítimos.
 */
export interface LegitDomain {
  readonly domain: string;
  readonly generic?: boolean;
}

export const LEGIT_DOMAINS: readonly LegitDomain[] = [
  // Wallets
  { domain: 'metamask.io' }, { domain: 'metamask.com' }, { domain: 'rabby.io' },
  { domain: 'phantom.app' }, { domain: 'phantom.com', generic: true }, { domain: 'solflare.com' },
  { domain: 'backpack.app', generic: true }, { domain: 'rainbow.me', generic: true },
  { domain: 'trustwallet.com' }, { domain: 'exodus.com', generic: true }, { domain: 'ledger.com', generic: true },
  { domain: 'trezor.io' }, { domain: 'safe.global', generic: true }, { domain: 'coinbase.com' },
  { domain: 'walletconnect.com' }, { domain: 'walletconnect.org' }, { domain: 'reown.com' },
  { domain: 'myetherwallet.com' }, { domain: 'zerion.io' }, { domain: 'argent.xyz', generic: true },
  // DEX / DeFi EVM
  { domain: 'uniswap.org' }, { domain: 'app.uniswap.org' }, { domain: 'pancakeswap.finance' },
  { domain: 'sushi.com', generic: true }, { domain: 'curve.fi', generic: true }, { domain: 'curve.finance', generic: true },
  { domain: 'balancer.fi', generic: true }, { domain: 'aave.com' }, { domain: 'app.aave.com' },
  { domain: 'compound.finance', generic: true }, { domain: 'lido.fi' }, { domain: 'stake.lido.fi' },
  { domain: 'makerdao.com' }, { domain: 'sky.money', generic: true }, { domain: 'spark.fi', generic: true },
  { domain: '1inch.io' }, { domain: '1inch.com' }, { domain: 'cow.fi', generic: true }, { domain: 'swap.cow.fi' },
  { domain: 'matcha.xyz', generic: true }, { domain: '0x.org', generic: true }, { domain: 'paraswap.io' }, { domain: 'velora.xyz' },
  { domain: 'eigenlayer.xyz' }, { domain: 'pendle.finance' }, { domain: 'ethena.fi' }, { domain: 'morpho.org' },
  { domain: 'gmx.io', generic: true }, { domain: 'dydx.exchange' }, { domain: 'dydx.trade' }, { domain: 'hyperliquid.xyz' },
  { domain: 'convexfinance.com' }, { domain: 'yearn.fi' }, { domain: 'frax.finance' }, { domain: 'rocketpool.net' },
  { domain: 'etherfi.io' }, { domain: 'ether.fi', generic: true }, { domain: 'renzoprotocol.com' }, { domain: 'polymarket.com' },
  // Bridges / L2
  { domain: 'arbitrum.io' }, { domain: 'bridge.arbitrum.io' }, { domain: 'portal.arbitrum.io' },
  { domain: 'optimism.io', generic: true }, { domain: 'base.org', generic: true }, { domain: 'zksync.io' }, { domain: 'polygon.technology', generic: true },
  { domain: 'across.to', generic: true }, { domain: 'stargate.finance', generic: true }, { domain: 'layerzero.network' },
  { domain: 'hop.exchange', generic: true }, { domain: 'synapseprotocol.com' }, { domain: 'jumper.exchange', generic: true },
  { domain: 'li.fi', generic: true }, { domain: 'relay.link', generic: true }, { domain: 'wormhole.com' },
  { domain: 'portalbridge.com' }, { domain: 'debridge.finance' }, { domain: 'orbiter.finance', generic: true },
  // NFT
  { domain: 'opensea.io' }, { domain: 'blur.io', generic: true }, { domain: 'magiceden.io' }, { domain: 'magiceden.us' },
  { domain: 'looksrare.org' }, { domain: 'x2y2.io' }, { domain: 'rarible.com' }, { domain: 'foundation.app', generic: true },
  { domain: 'zora.co', generic: true }, { domain: 'tensor.trade', generic: true }, { domain: 'manifold.xyz', generic: true },
  // Solana
  { domain: 'jup.ag', generic: true }, { domain: 'raydium.io' }, { domain: 'orca.so', generic: true },
  { domain: 'meteora.ag' }, { domain: 'marinade.finance', generic: true }, { domain: 'jito.network' }, { domain: 'drift.trade', generic: true },
  { domain: 'kamino.finance' }, { domain: 'marginfi.com' }, { domain: 'pump.fun', generic: true },
  { domain: 'solana.com', generic: true }, { domain: 'tensor.so', generic: true }, { domain: 'sanctum.so', generic: true }, { domain: 'solscan.io' },
  // Exploradores y herramientas
  { domain: 'etherscan.io' }, { domain: 'arbiscan.io' }, { domain: 'basescan.org' }, { domain: 'polygonscan.com' },
  { domain: 'bscscan.com' }, { domain: 'optimistic.etherscan.io' }, { domain: 'blockscout.com' },
  { domain: 'revoke.cash' }, { domain: 'debank.com' }, { domain: 'zapper.xyz' }, { domain: 'dune.com', generic: true },
  { domain: 'ethereum.org', generic: true }, { domain: 'ens.domains', generic: true }, { domain: 'app.ens.domains', generic: true }, { domain: 'tenderly.co' },
  { domain: 'defillama.com' }, { domain: 'coingecko.com' }, { domain: 'coinmarketcap.com' },
  // Exchanges centralizados
  { domain: 'binance.com' }, { domain: 'kraken.com' }, { domain: 'okx.com', generic: true }, { domain: 'bybit.com' },
  { domain: 'kucoin.com' }, { domain: 'gemini.com', generic: true }, { domain: 'bitget.com' }, { domain: 'crypto.com', generic: true },
];

/**
 * Dominios que nunca se bloquean como entrada exacta de una lista pública:
 * plataformas compartidas donde bloquear el dominio entero rompería miles de
 * sitios legítimos (sus subdominios sí se pueden bloquear). Se detectaron
 * entradas así en las listas reales (p. ej. "sites.google.com", "r2.dev").
 */
export const NEVER_BLOCK_EXACT: ReadonlySet<string> = new Set([
  'google.com', 'sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle',
  'storage.googleapis.com', 'googleapis.com', 'firebasestorage.googleapis.com', 'translate.goog',
  'github.com', 'github.io', 'raw.githubusercontent.com', 'gitlab.io', 'gitbook.io',
  'pages.dev', 'workers.dev', 'r2.dev', 'vercel.app', 'netlify.app', 'web.app', 'firebaseapp.com',
  'herokuapp.com', 'onrender.com', 'fly.dev', 'railway.app', 'replit.app', 'surge.sh',
  'webflow.io', 'wixsite.com', 'weebly.com', 'blogspot.com', 'wordpress.com', 'medium.com',
  'notion.site', 'godaddysites.com', 'square.site', 'typedream.app', 'framer.website',
  'amplifyapp.com', 'azurewebsites.net', 'appspot.com', 's3.amazonaws.com', 'amazonaws.com',
  'cloudfront.net', 'cloudflare-ipfs.com', 'ipfs.io', 'dweb.link', 'eth.limo', 'eth.link',
  'fleek.co', 'on-fleek.app', 'pinata.cloud', 'mypinata.cloud', 'ngrok.io', 'ngrok-free.app',
  'ddns.net', 'duckdns.org', 'hopto.org', 'zapto.org', 'sytes.net', 'servehttp.com',
  'twitter.com', 'x.com', 't.co', 'discord.com', 'discord.gg', 't.me', 'telegram.org',
  'youtube.com', 'youtu.be', 'facebook.com', 'instagram.com', 'linktr.ee', 'bit.ly',
  'microsoft.com', 'apple.com', 'cloudflare.com', 'trycloudflare.com',
]);
