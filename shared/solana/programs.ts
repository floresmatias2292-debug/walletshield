/**
 * Programas de Solana conocidos. Los del sistema y SPL se verifican en
 * tests contra @solana/web3.js y @solana/spl-token; los de DEX se copiaron
 * de los repositorios oficiales de cada proyecto (2026-11-09).
 * Un programa conocido solo cambia la etiqueta que se muestra: los riesgos
 * (cambios de dueño, aprobaciones) se detectan igual.
 */
export const SYSTEM = '11111111111111111111111111111111';
export const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';
export const STAKE = 'Stake11111111111111111111111111111111111111';
export const LOADER_UPGRADEABLE = 'BPFLoaderUpgradeab1e11111111111111111111111';
export const MEMO = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const MEMO_V1 = 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo';

export const PROGRAM_LABELS: Readonly<Record<string, string>> = {
  [SYSTEM]: 'System Program',
  [TOKEN]: 'SPL Token',
  [TOKEN_2022]: 'SPL Token-2022',
  [ATA]: 'Associated Token Account',
  [COMPUTE_BUDGET]: 'Compute Budget',
  [STAKE]: 'Stake Program',
  [LOADER_UPGRADEABLE]: 'BPF Upgradeable Loader',
  [MEMO]: 'Memo',
  [MEMO_V1]: 'Memo (v1)',
  // DEX — repos oficiales
  JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4: 'Jupiter v6', // jup-ag/instruction-parser
  '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8': 'Raydium AMM v4', // raydium-sdk-V2
  CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK: 'Raydium CLMM',
  CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C: 'Raydium CPMM',
  whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc: 'Orca Whirlpools', // orca-so/whirlpools
  LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo: 'Meteora DLMM', // MeteoraAg/dlmm-sdk
};

/** Programas que no mueven fondos por sí mismos. */
export const BENIGN_PROGRAMS: ReadonlySet<string> = new Set([COMPUTE_BUDGET, MEMO, MEMO_V1, ATA]);

export const U64_MAX = (1n << 64n) - 1n;
