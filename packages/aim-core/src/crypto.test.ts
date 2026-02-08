import { describe, it, expect } from 'vitest';
import * as nacl from 'tweetnacl';
import { sign, verify } from './crypto';

describe('crypto', () => {
  const keypair = nacl.sign.keyPair();
  const message = new TextEncoder().encode('hello world');

  describe('sign', () => {
    it('produces a 64-byte signature', () => {
      const sig = sign(message, keypair.secretKey);
      expect(sig.length).toBe(64);
    });
  });

  describe('verify', () => {
    it('verifies a valid signature', () => {
      const sig = sign(message, keypair.secretKey);
      expect(verify(message, sig, keypair.publicKey)).toBe(true);
    });

    it('rejects a tampered message', () => {
      const sig = sign(message, keypair.secretKey);
      const tampered = new TextEncoder().encode('hello tampered');
      expect(verify(tampered, sig, keypair.publicKey)).toBe(false);
    });

    it('rejects a signature from a different key', () => {
      const otherKeypair = nacl.sign.keyPair();
      const sig = sign(message, otherKeypair.secretKey);
      expect(verify(message, sig, keypair.publicKey)).toBe(false);
    });
  });
});
