/**
 * ARP crypto module barrel (scaffolding, AIComply P1).
 *
 * Public entry point for hybrid Ed25519 + ML-DSA signing primitives used by:
 * - Capability manifest loader (verifies Ed25519+ML-DSA-65 signature before load)
 * - `verifyClassification()` (verifies Ed25519+ML-DSA-44 on NanoMind-Guard output)
 * - AIComply P1 integration (AC-001, AC-002, AC-010, AC-014, AC-015, AC-016)
 */

export type {
  MLDsaVariant,
  HybridAlgorithm,
  HybridKeyPair,
  HybridPublicKey,
  HybridSignature,
  EncodedHybridSignature,
  HybridVerifyResult,
} from './types';

export {
  NotImplementedError,
  generateHybridKeyPair,
  hybridSign,
  hybridVerify,
  hybridAlgorithmFor,
} from './hybrid-signing';
