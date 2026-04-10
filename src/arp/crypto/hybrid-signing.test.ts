/**
 * Scaffolding tests for arp/crypto.
 *
 * These tests verify the public surface exists and that all stub functions
 * throw `NotImplementedError`. They will be replaced with real round-trip
 * tests when hybrid signing is implemented in the follow-up commit.
 */

import { describe, it, expect } from 'vitest';
import {
  NotImplementedError,
  generateHybridKeyPair,
  hybridSign,
  hybridVerify,
  hybridAlgorithmFor,
} from './index';
import type { HybridKeyPair, HybridPublicKey, HybridSignature } from './index';

describe('arp/crypto scaffolding', () => {
  it('resolves the @noble/ed25519 dependency', () => {
    // Fails at module load time if the dep is missing or the version is wrong.
    // The import is inside hybrid-signing.ts; if we got here, it loaded.
    expect(typeof NotImplementedError).toBe('function');
  });

  it('resolves the @noble/post-quantum/ml-dsa dependency', () => {
    // Same as above: module load covers the dep presence.
    expect(typeof NotImplementedError).toBe('function');
  });

  it('maps ML-DSA variants to canonical hybrid algorithm strings', () => {
    expect(hybridAlgorithmFor('ML-DSA-44')).toBe('Ed25519+ML-DSA-44');
    expect(hybridAlgorithmFor('ML-DSA-65')).toBe('Ed25519+ML-DSA-65');
    expect(hybridAlgorithmFor('ML-DSA-87')).toBe('Ed25519+ML-DSA-87');
  });

  it('generateHybridKeyPair is scaffolding (throws NotImplementedError)', async () => {
    await expect(generateHybridKeyPair('ML-DSA-65')).rejects.toBeInstanceOf(
      NotImplementedError,
    );
  });

  it('hybridSign is scaffolding (throws NotImplementedError)', async () => {
    const fakeKeyPair = {} as HybridKeyPair;
    await expect(hybridSign(new Uint8Array([1, 2, 3]), fakeKeyPair)).rejects.toBeInstanceOf(
      NotImplementedError,
    );
  });

  it('hybridVerify is scaffolding (throws NotImplementedError)', async () => {
    const fakeSig = {} as HybridSignature;
    const fakePub = {} as HybridPublicKey;
    await expect(
      hybridVerify(new Uint8Array([1, 2, 3]), fakeSig, fakePub),
    ).rejects.toBeInstanceOf(NotImplementedError);
  });
});
