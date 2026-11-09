/**
 * Transacciones construidas con @solana/web3.js y @solana/spl-token (los
 * mismos bytes que recibe Phantom). Drainers: patrones públicos de "owner
 * change", SetAuthority, delegación ilimitada y vaciado multi-token.
 */
import { describe, expect, it } from 'vitest';
import {
  AddressLookupTableAccount, ComputeBudgetProgram, Keypair, PublicKey, StakeProgram, SystemProgram,
  Transaction, TransactionInstruction, TransactionMessage, VersionedTransaction,
} from '@solana/web3.js';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID, AuthorityType, createApproveInstruction, createAssociatedTokenAccountIdempotentInstruction,
  createCloseAccountInstruction, createSetAuthorityInstruction, createTransferCheckedInstruction, createTransferInstruction,
  TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import { analyzeSolanaRequest } from '../../shared/solana/analyzer';
import { decodeBase58, encodeBase58 } from '../../shared/solana/base58';
import * as P from '../../shared/solana/programs';
import type { RiskLevel } from '../../shared/risk';

const kp = (n: number) => Keypair.fromSeed(new Uint8Array(32).fill(n));
const user = kp(1).publicKey;
const attacker = kp(9).publicKey;
const mint = kp(3).publicKey;
const ata = (n: number) => kp(20 + n).publicKey;
const blockhash = encodeBase58(new Uint8Array(32).fill(7));
const input = { pageHost: 'app.example.so', siteRisk: 'none' as RiskLevel };
const order = { none: 0, low: 1, medium: 2, high: 3 } as const;

function legacy(...ixs: TransactionInstruction[]) {
  const tx = new Transaction({ feePayer: user, recentBlockhash: blockhash }).add(...ixs);
  return { b64: Buffer.from(tx.serializeMessage()).toString('base64'), wire: false };
}
function v0(ixs: TransactionInstruction[], luts: AddressLookupTableAccount[] = []) {
  const msg = new TransactionMessage({ payerKey: user, recentBlockhash: blockhash, instructions: ixs }).compileToV0Message(luts);
  return { b64: Buffer.from(new VersionedTransaction(msg).serialize()).toString('base64'), wire: true };
}
const sign = (...txs: Array<{ b64: string; wire: boolean }>) => analyzeSolanaRequest('solana:signTransaction', [{ txs }], input);
const codes = (a: { findings: readonly { code: string }[] }) => a.findings.map((f) => f.code);

describe('constantes verificadas contra las librerías oficiales', () => {
  it('IDs de programas', () => {
    expect(P.SYSTEM).toBe(SystemProgram.programId.toBase58());
    expect(P.TOKEN).toBe(TOKEN_PROGRAM_ID.toBase58());
    expect(P.TOKEN_2022).toBe(TOKEN_2022_PROGRAM_ID.toBase58());
    expect(P.ATA).toBe(ASSOCIATED_TOKEN_PROGRAM_ID.toBase58());
    expect(P.COMPUTE_BUDGET).toBe(ComputeBudgetProgram.programId.toBase58());
    expect(P.STAKE).toBe(StakeProgram.programId.toBase58());
    for (const id of [...Object.keys(P.PROGRAM_LABELS), P.LOADER_UPGRADEABLE]) expect(decodeBase58(id)?.length, id).toBe(32);
  });
  it('base58 ida y vuelta', () => {
    for (const k of [user, attacker, PublicKey.default]) expect(encodeBase58(decodeBase58(k.toBase58())!)).toBe(k.toBase58());
    expect(decodeBase58('0OIl')).toBeNull();
  });
});

describe('DRAINERS de Solana → riesgo alto', () => {
  it('SetAuthority: cambia el dueño de tu cuenta de tokens (legacy)', () => {
    const a = sign(legacy(createSetAuthorityInstruction(ata(1), user, AuthorityType.AccountOwner, attacker)));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('sol-owner-change');
    expect(a.hardBlockInStrict).toBe(true);
  });
  it('SetAuthority escondido en una v0 con cuentas de una lookup table', () => {
    const lut = new AddressLookupTableAccount({ key: kp(50).publicKey, state: { deactivationSlot: BigInt('18446744073709551615'), lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0, addresses: [ata(1), ata(2), attacker] } });
    const a = sign(v0([ComputeBudgetProgram.setComputeUnitLimit({ units: 200000 }), createSetAuthorityInstruction(ata(1), user, AuthorityType.AccountOwner, attacker)], [lut]));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('sol-owner-change');
  });
  it('System Assign: tu wallet pasa a ser de otro programa ("owner change")', () => {
    const a = sign(legacy(SystemProgram.assign({ accountPubkey: user, programId: attacker })));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('sol-assign');
  });
  it('vaciado multi-token + SOL hacia el atacante', () => {
    const a = sign(v0([
      createTransferInstruction(ata(1), ata(11), user, 5_000_000n),
      createTransferInstruction(ata(2), ata(12), user, 900_000_000n),
      createTransferInstruction(ata(3), ata(13), user, 77n),
      SystemProgram.transfer({ fromPubkey: user, toPubkey: attacker, lamports: 3_200_000_000 }),
    ]));
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('sol-multi-drain');
    expect(a.summary.join(' ')).toMatch(/3,2 SOL/);
  });
  it('delegación ilimitada (Approve u64::MAX)', () => {
    const a = sign(legacy(createApproveInstruction(ata(1), attacker, user, BigInt('18446744073709551615'))));
    expect(a.risk).toBe('high');
    expect(a.summary.join(' ')).toMatch(/ILIMITADO/);
  });
  it('cambio de autoridad de staking', () => {
    const tx = StakeProgram.authorize({ stakePubkey: kp(30).publicKey, authorizedPubkey: user, newAuthorizedPubkey: attacker, stakeAuthorizationType: { index: 1 } });
    expect(codes(sign(legacy(...tx.instructions)))).toContain('sol-stake-authority');
  });
  it('cambio de autoridad de un durable nonce', () => {
    const tx = SystemProgram.nonceAuthorize({ noncePubkey: kp(31).publicKey, authorizedPubkey: user, newAuthorizedPubkey: attacker });
    expect(sign(legacy(tx)).risk).toBe('high');
  });
  it('signMessage con una transacción serializada disfrazada de mensaje', () => {
    const tx = new Transaction({ feePayer: user, recentBlockhash: blockhash }).add(SystemProgram.transfer({ fromPubkey: user, toPubkey: attacker, lamports: 1 }));
    const a = analyzeSolanaRequest('solana:signMessage', [{ message: { b64: Buffer.from(tx.serializeMessage()).toString('base64'), wire: false } }], input);
    expect(a.risk).toBe('high');
    expect(codes(a)).toContain('sol-message-tx');
  });
  it('Sign In With Solana para otro dominio', () => {
    const msg = Buffer.from(`jup.ag wants you to sign in with your Solana account:\n${user.toBase58()}\n\nNonce: 123`).toString('base64');
    expect(analyzeSolanaRequest('solana:signMessage', [{ message: { b64: msg, wire: false } }], { ...input, pageHost: 'jup-ag-claim.xyz' }).risk).toBe('high');
    expect(analyzeSolanaRequest('solana:signIn', [{ signIn: { domain: 'jup.ag' } }], { ...input, pageHost: 'jup-ag-claim.xyz' }).risk).toBe('high');
  });
  it('sitio sospechoso eleva cualquier transacción', () => {
    const a = analyzeSolanaRequest('solana:signTransaction', [{ txs: [legacy(SystemProgram.transfer({ fromPubkey: user, toPubkey: attacker, lamports: 1000 }))] }], { ...input, siteRisk: 'medium' });
    expect(a.risk).toBe('high');
  });
  it('datos corruptos → alto (nunca silencio)', () => {
    expect(sign({ b64: Buffer.from([1, 2, 3]).toString('base64'), wire: true }).risk).toBe('high');
  });
});

describe('LEGÍTIMOS → sin falsos positivos', () => {
  it('swap estilo Jupiter (v0, lookup tables, compute budget, ATA, programa de Jupiter)', () => {
    const lut = new AddressLookupTableAccount({ key: kp(60).publicKey, state: { deactivationSlot: BigInt('18446744073709551615'), lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0, addresses: Array.from({ length: 20 }, (_, i) => kp(70 + i).publicKey) } });
    const jup = new PublicKey('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4');
    const a = sign(v0([
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 50000 }),
      createAssociatedTokenAccountIdempotentInstruction(user, ata(5), user, mint),
      new TransactionInstruction({ programId: jup, keys: [{ pubkey: user, isSigner: true, isWritable: true }, ...Array.from({ length: 12 }, (_, i) => ({ pubkey: kp(70 + i).publicKey, isSigner: false, isWritable: i % 2 === 0 }))], data: Buffer.from('e517cb977ae3ad2a0100000000', 'hex') }),
    ], [lut]));
    expect(order[a.risk]).toBeLessThanOrEqual(order.low);
    expect(a.summary.join(' ')).toMatch(/Jupiter v6/);
  });
  it('envío simple de SOL y de un token', () => {
    expect(sign(legacy(SystemProgram.transfer({ fromPubkey: user, toPubkey: attacker, lamports: 100_000_000 }))).risk).toBe('none');
    const a = sign(legacy(createTransferCheckedInstruction(ata(1), mint, ata(9), user, 2_500_000n, 6)));
    expect(a.risk).toBe('none');
    expect(a.summary[0]).toMatch(/2,5/);
  });
  it('cerrar una cuenta vacía devolviendo el depósito a ti', () => {
    expect(sign(legacy(createCloseAccountInstruction(ata(1), user, user))).risk).toBe('none');
  });
  it('SIWS del mismo sitio y mensaje de texto', () => {
    const msg = Buffer.from(`app.example.so wants you to sign in with your Solana account:\n${user.toBase58()}`).toString('base64');
    expect(analyzeSolanaRequest('solana:signMessage', [{ message: { b64: msg, wire: false } }], input).risk).toBe('none');
    const txt = Buffer.from('Verifica que eres el dueño: 8f3a').toString('base64');
    expect(analyzeSolanaRequest('solana:signMessage', [{ message: { b64: txt, wire: false } }], input).risk).toBe('low');
  });
  it('lote de 6 transacciones → advertencia media', () => {
    const t = legacy(SystemProgram.transfer({ fromPubkey: user, toPubkey: attacker, lamports: 1 }));
    expect(codes(sign(t, t, t, t, t, t))).toContain('sol-batch');
  });
  it('analiza en menos de 1 ms en promedio', () => {
    const t = v0([createSetAuthorityInstruction(ata(1), user, AuthorityType.AccountOwner, attacker), ComputeBudgetProgram.setComputeUnitLimit({ units: 1 })]);
    const t0 = performance.now();
    for (let i = 0; i < 300; i++) sign(t);
    expect((performance.now() - t0) / 300).toBeLessThan(1);
  });
});
