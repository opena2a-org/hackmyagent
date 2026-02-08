import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createIdentity, loadIdentity, getOrCreateIdentity, getSecretKey, getPublicKey } from './identity';

describe('identity', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('createIdentity', () => {
    it('generates a valid Ed25519 identity', () => {
      const id = createIdentity(tmpDir, 'test-agent');

      expect(id.agentId).toMatch(/^aim_/);
      expect(id.agentName).toBe('test-agent');
      expect(id.publicKey).toBeTruthy();
      expect(id.secretKey).toBeTruthy();
      expect(id.createdAt).toBeTruthy();

      // Public key should be 32 bytes (base64)
      const pubKeyBytes = Buffer.from(id.publicKey, 'base64');
      expect(pubKeyBytes.length).toBe(32);

      // Secret key should be 64 bytes (base64)
      const secKeyBytes = Buffer.from(id.secretKey, 'base64');
      expect(secKeyBytes.length).toBe(64);
    });

    it('writes identity.json to disk', () => {
      createIdentity(tmpDir, 'test-agent');
      const filePath = path.join(tmpDir, 'identity.json');
      expect(fs.existsSync(filePath)).toBe(true);

      const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(raw.agentName).toBe('test-agent');
      expect(raw.agentId).toMatch(/^aim_/);
    });

    it('creates the directory if it does not exist', () => {
      const nested = path.join(tmpDir, 'deep', 'nested');
      createIdentity(nested, 'test-agent');
      expect(fs.existsSync(path.join(nested, 'identity.json'))).toBe(true);
    });
  });

  describe('loadIdentity', () => {
    it('returns null when no identity exists', () => {
      expect(loadIdentity(tmpDir)).toBeNull();
    });

    it('loads a previously created identity', () => {
      const created = createIdentity(tmpDir, 'test-agent');
      const loaded = loadIdentity(tmpDir);

      expect(loaded).not.toBeNull();
      expect(loaded!.agentId).toBe(created.agentId);
      expect(loaded!.publicKey).toBe(created.publicKey);
      expect(loaded!.secretKey).toBe(created.secretKey);
    });
  });

  describe('getOrCreateIdentity', () => {
    it('creates identity on first call', () => {
      const id = getOrCreateIdentity(tmpDir, 'test-agent');
      expect(id.agentId).toMatch(/^aim_/);
      expect(id.agentName).toBe('test-agent');
      // Should not include secretKey
      expect((id as unknown as Record<string, unknown>).secretKey).toBeUndefined();
    });

    it('returns same identity on subsequent calls', () => {
      const first = getOrCreateIdentity(tmpDir, 'test-agent');
      const second = getOrCreateIdentity(tmpDir, 'test-agent');
      expect(first.agentId).toBe(second.agentId);
      expect(first.publicKey).toBe(second.publicKey);
    });
  });

  describe('getSecretKey / getPublicKey', () => {
    it('returns null when no identity exists', () => {
      expect(getSecretKey(tmpDir)).toBeNull();
      expect(getPublicKey(tmpDir)).toBeNull();
    });

    it('returns keys after identity creation', () => {
      createIdentity(tmpDir, 'test-agent');

      const sk = getSecretKey(tmpDir);
      expect(sk).not.toBeNull();
      expect(sk!.length).toBe(64);

      const pk = getPublicKey(tmpDir);
      expect(pk).not.toBeNull();
      expect(pk!.length).toBe(32);
    });
  });
});
