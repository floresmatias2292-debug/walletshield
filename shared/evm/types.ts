import type { RiskLevel } from '../risk';

export type FindingCode =
  | 'eth-sign' | 'blind-hash' | 'binary-message' | 'text-message' | 'siwe' | 'siwe-mismatch'
  | 'approval' | 'approval-revoke' | 'unlimited-approval' | 'approval-for-all' | 'counterparty'
  | 'bad-address' | 'permit' | 'permit2' | 'permit-batch' | 'permit-transfer' | 'long-expiry' | 'fake-contract'
  | 'nft-listing' | 'nft-sale-zero' | 'bulk-orders' | 'blur-bulk'
  | 'native-drain' | 'value-to-contract' | 'drainer-function' | 'token-transfer' | 'nft-transfer'
  | 'eip7702' | 'batch-calls' | 'contract-creation' | 'chain-mismatch' | 'typed-data' | 'legacy-typed-data'
  | 'suspicious-site' | 'undecodable' | 'add-chain' | 'grant-permissions' | 'unknown-method';

export interface Finding {
  readonly code: FindingCode;
  readonly risk: RiskLevel;
  /** Explicación en español, en lenguaje claro. */
  readonly text: string;
}

export interface Analysis {
  readonly method: string;
  readonly risk: RiskLevel;
  /** Título corto: qué estás por hacer. */
  readonly title: string;
  /** Líneas "qué autorizas, a quién y por cuánto". */
  readonly summary: readonly string[];
  readonly findings: readonly Finding[];
  /** En modo estricto, ciertas operaciones se bloquean sin opción de continuar. */
  readonly hardBlockInStrict: boolean;
}

export interface TokenInfo {
  readonly symbol: string | null;
  readonly decimals: number | null;
}

/** Consultas de solo lectura que el analizador puede necesitar. */
export type Lookup =
  | { readonly kind: 'code'; readonly address: string }
  | { readonly kind: 'balance'; readonly address: string }
  | { readonly kind: 'token'; readonly address: string }
  | { readonly kind: 'tokenBalance'; readonly address: string; readonly owner: string };

export function lookupKey(l: Lookup): string {
  return l.kind === 'tokenBalance' ? `${l.kind}:${l.address}:${l.owner}` : `${l.kind}:${l.address}`;
}
