/**
 * Configuración validada. El monitor SOLO acepta direcciones públicas: si
 * detecta algo con forma de clave privada o frase semilla, se niega a correr.
 */
import type { Env } from './types';

export interface ChainCfg {
  readonly id: number;
  readonly name: string;
  readonly rpc: string;
  /** Bloques de margen ante reorgs. */
  readonly confirmations: number;
  /** Máximo de bloques por eth_getLogs (límite de RPC públicos). */
  readonly chunk: number;
  /** Máximo de bloques a recorrer por ejecución (si se atrasa, se pone al día de a poco). */
  readonly maxRange: number;
  readonly explorer: string;
}

export interface Config {
  readonly evm: readonly string[];
  readonly solana: readonly string[];
  readonly chains: readonly ChainCfg[];
  readonly solRpc: string;
  readonly telegram: { readonly token: string; readonly chatId: string; readonly base: string } | null;
}

const EVM_RE = /^0x[0-9a-fA-F]{40}$/;
const SOL_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const PRIVATE_KEY_RE = /^(0x)?[0-9a-fA-F]{64}$/;

export class ConfigError extends Error {}

function list(v: string | undefined): string[] {
  return (v ?? '').split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
}

/** Solo HTTPS (HTTP únicamente hacia localhost, para pruebas locales). */
function httpsUrl(v: string | undefined, fallback: string): string {
  const u = (v ?? '').trim() || fallback;
  let parsed: URL;
  try {
    parsed = new URL(u);
  } catch {
    throw new ConfigError('URL inválida en la configuración');
  }
  const local = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) throw new ConfigError(`Solo se permiten URLs https: ${parsed.host}`);
  return u.replace(/\/$/, '');
}

export function loadConfig(env: Env): Config {
  const rawEvm = list(env.EVM_ADDRESSES);
  const rawSol = list(env.SOLANA_ADDRESSES);
  for (const x of [...rawEvm, ...rawSol]) {
    // Defensa: una clave privada (64 hex) o una frase semilla (12/24 palabras) jamás deben estar aquí.
    if (PRIVATE_KEY_RE.test(x)) throw new ConfigError('Eso parece una CLAVE PRIVADA. Usa solo direcciones públicas.');
  }
  if ((env.EVM_ADDRESSES ?? '').trim().split(/\s+/).length >= 12 && rawEvm.every((w) => /^[a-z]+$/.test(w))) {
    throw new ConfigError('Eso parece una FRASE SEMILLA. Usa solo direcciones públicas.');
  }
  const bad = [...rawEvm.filter((a) => !EVM_RE.test(a)), ...rawSol.filter((a) => !SOL_RE.test(a))];
  if (bad.length) throw new ConfigError(`Direcciones inválidas: ${bad.map((b) => b.slice(0, 12)).join(', ')}`);
  if (rawEvm.length + rawSol.length > 20) throw new ConfigError('Máximo 20 direcciones.');

  const ids = list(env.EVM_CHAINS || '1,42161').map(Number);
  const chains: ChainCfg[] = [];
  for (const id of ids) {
    if (id === 1) chains.push({ id, name: 'Ethereum', rpc: httpsUrl(env.ETH_RPC_URL, 'https://ethereum-rpc.publicnode.com'), confirmations: 3, chunk: 500, maxRange: 3000, explorer: 'https://etherscan.io' });
    else if (id === 42161) chains.push({ id, name: 'Arbitrum', rpc: httpsUrl(env.ARB_RPC_URL, 'https://arb1.arbitrum.io/rpc'), confirmations: 20, chunk: 2000, maxRange: 12000, explorer: 'https://arbiscan.io' });
    else throw new ConfigError(`Cadena no soportada: ${id} (usa 1 y/o 42161)`);
  }
  const token = (env.TELEGRAM_BOT_TOKEN ?? '').trim();
  const chatId = (env.TELEGRAM_CHAT_ID ?? '').trim();
  return {
    evm: [...new Set(rawEvm.map((a) => a.toLowerCase()))],
    solana: [...new Set(rawSol)],
    chains,
    solRpc: httpsUrl(env.SOL_RPC_URL, 'https://api.mainnet-beta.solana.com'),
    telegram: token && chatId ? { token, chatId, base: httpsUrl(env.TELEGRAM_API_BASE, 'https://api.telegram.org') } : null,
  };
}
