/**
 * Hybrid Ed25519 + ML-DSA signing (scaffolding, AIComply P1).
 *
 * STATUS: SCAFFOLDING ONLY. All functions below throw `NotImplementedError`.
 * The real implementation lands in the next commit on `feat/arp-crypto`.
 *
 * When implementing:
 * - Use `@noble/ed25519` for the classical half
 * - Use `@noble/post-quantum`'s `ml_dsa44`, `ml_dsa65`, `ml_dsa87` for the PQ half
 * - Mirror the API shape of `agent-identity-management/sdk/typescript/src/crypto/pqc.ts`
 * - Enforce `KEY_SIZES` validation from the AIM reference
 * - `hybridVerify()` must be constant-time and must NOT short-circuit on the first failure
 *   (always evaluate both halves to avoid side-channel leakage)
 * - Benchmark ML-DSA-44 sign p99 under 2ms on the dev laptop per AC-016
 *
 * The exported signatures are stable; downstream code (`verifyClassification`,
 * capability manifest loader, AIComply P1 integration) may import and type-check
 * against these stubs before the real implementation lands.
 */

import type {
  HybridAlgorithm,
  HybridKeyPair,
  HybridPublicKey,
  HybridSignature,
  HybridVerifyResult,
  MLDsaVariant,
} from './types';

// Touch the dependency imports so TypeScript resolves them and any wrong install
// fails at build time, not at first runtime call. These are re-imported for real
// use in the follow-up commit.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import * as _ed25519 from '@noble/ed25519';
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import * as _pq from '@noble/post-quantum/ml-dsa';

/**
 * Error thrown by all scaffolding stubs. Catching code can detect the scaffolding
 * phase by `err instanceof NotImplementedError` and fail closed (parse-to-deny).
 */
export class NotImplementedError extends Error {
  constructor(fn: string) {
    super(`[arp/crypto] ${fn} is scaffolding only. Implement in feat/arp-crypto follow-up commit.`);
    this.name = 'NotImplementedError';
  }
}

/**
 * Generate a hybrid Ed25519 + ML-DSA key pair.
 * @param variant ML-DSA parameter set. 44 for low-cost identity, 65 for manifests,
 *                87 for high-value root keys.
 */
export async function generateHybridKeyPair(
  variant: MLDsaVariant,
): Promise<HybridKeyPair> {
  void variant;
  throw new NotImplementedError('generateHybridKeyPair');
}

/**
 * Sign a payload with a hybrid key pair. Both halves (Ed25519 and ML-DSA) sign
 * the SAME payload bytes; the returned signature carries both.
 */
export async function hybridSign(
  payload: Uint8Array,
  keyPair: HybridKeyPair,
): Promise<HybridSignature> {
  void payload;
  void keyPair;
  throw new NotImplementedError('hybridSign');
}

/**
 * Verify a hybrid signature. Returns `{valid: true}` only if BOTH halves verify.
 * Invalid or missing signatures MUST trigger parse-to-deny via the caller
 * (CR-001 code path in `src/arp/proxy/server.ts` and `src/arp/intelligence/coordinator.ts`).
 */
export async function hybridVerify(
  payload: Uint8Array,
  signature: HybridSignature,
  publicKey: HybridPublicKey,
): Promise<HybridVerifyResult> {
  void payload;
  void signature;
  void publicKey;
  throw new NotImplementedError('hybridVerify');
}

/**
 * Return the canonical hybrid algorithm string for a given ML-DSA variant.
 * Stable helper, safe to use from scaffolding.
 */
export function hybridAlgorithmFor(variant: MLDsaVariant): HybridAlgorithm {
  switch (variant) {
    case 'ML-DSA-44':
      return 'Ed25519+ML-DSA-44';
    case 'ML-DSA-65':
      return 'Ed25519+ML-DSA-65';
    case 'ML-DSA-87':
      return 'Ed25519+ML-DSA-87';
  }
}
