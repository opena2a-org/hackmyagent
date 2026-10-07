import { describe, it, expect } from 'vitest';
import { mkdir, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { isPrivateKeyValue, privateKeyFieldsInJson } from '../../src/hardening/embedded-private-key';
import { tempDir } from '../helpers/temp-dir';

/**
 * #577 — an Ed25519 private key written as a JSON VALUE was invisible to
 * `secure`. Measured before the fix: a tree holding only
 * `.opena2a/aim/identity.json` (the shape `fix-all --with-aim` used to write:
 * base64 `publicKey` plus base64 `secretKey`) scored 98/100 with zero credential
 * or key findings, while the same key as a `.key` file is CRED-002 CRITICAL.
 *
 * Every key below is generated at run time, so no committed line carries a
 * key-shaped literal.
 */

type Finding = { checkId: string; severity: string; passed: boolean; file?: string; message: string; details?: Record<string, unknown> };

const IDENTITY_REL = path.join('.opena2a', 'aim', 'identity.json');

/** The serialisation aim-core writes: tweetnacl's 64-byte secretKey, base64. */
function aimIdentity(secretKey: string): string {
  return JSON.stringify({
    agentId: 'aim_FAKE',
    publicKey: randomBytes(32).toString('base64'),
    secretKey,
    agentName: 'FAKE-agent',
    createdAt: '2026-01-01T00:00:00.000Z',
  }, null, 2);
}

async function scanTree(contents: Record<string, string>): Promise<Finding[]> {
  const dir = tempDir('hma577-');
  for (const [rel, body] of Object.entries(contents)) {
    const full = path.join(dir, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, body);
  }
  const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
  return result.findings as Finding[];
}

describe('#577 private key embedded as a JSON value', () => {
  describe('privateKeyFieldsInJson', () => {
    it('finds a key in every raw encoding a keypair library writes', () => {
      const cases: Array<[string, string]> = [
        ['secretKey', randomBytes(64).toString('base64')],
        ['secretKey', randomBytes(32).toString('base64')],
        ['privateKey', randomBytes(32).toString('base64url')],
        ['private_key', '0x' + randomBytes(32).toString('hex')],
        ['PRIVATE-KEY', randomBytes(64).toString('hex')],
      ];
      for (const [field, value] of cases) {
        expect(privateKeyFieldsInJson(JSON.stringify({ [field]: value })), `${field}=${value.length} chars`).toEqual([field]);
      }
    });

    it('finds a key nested in an object or array, once per field name', () => {
      const doc = { wallets: [{ privateKey: randomBytes(32).toString('base64') }, { privateKey: randomBytes(32).toString('base64') }] };
      expect(privateKeyFieldsInJson(JSON.stringify(doc))).toEqual(['privateKey']);
    });

    it('does not report a placeholder, a public key, a wrong length, or an unrelated field', () => {
      const docs = [
        { secretKey: 'FAKE-PLACEHOLDER' },
        { privateKey: '0x' + '0'.repeat(64) },
        { privateKey: '0123456789abcdef'.repeat(4) },
        { publicKey: randomBytes(32).toString('base64') },
        { secretKey: randomBytes(48).toString('base64') },
        { secretKey: randomBytes(31).toString('base64') },
        { token: randomBytes(32).toString('base64') },
        { secretKey: { nested: true } },
      ];
      for (const doc of docs) expect(privateKeyFieldsInJson(JSON.stringify(doc)), JSON.stringify(doc)).toEqual([]);
    });

    it('rejects a base64 value whose padding does not match its length', () => {
      const body = randomBytes(32).toString('base64').replace(/=+$/, '');
      expect(isPrivateKeyValue(body)).toBe(true);
      expect(isPrivateKeyValue(body + '=')).toBe(true);
      expect(isPrivateKeyValue(body + '==')).toBe(false);
    });

    it('returns nothing for text that is not JSON', () => {
      expect(privateKeyFieldsInJson(`{"secretKey": "${randomBytes(32).toString('base64')}"`)).toEqual([]);
    });
  });

  describe('secure', () => {
    it('reports the aim identity file as CRED-002 CRITICAL, naming the field', async () => {
      const findings = await scanTree({ [IDENTITY_REL]: aimIdentity(randomBytes(64).toString('base64')) });
      const cred002 = findings.find((f) => f.checkId === 'CRED-002' && !f.passed);
      expect(cred002, 'CRED-002 for the embedded secretKey').toBeDefined();
      expect(cred002!.severity).toBe('critical');
      expect(cred002!.file).toBe(IDENTITY_REL);
      expect(cred002!.message).toContain(`${IDENTITY_REL} (secretKey field)`);
      expect(cred002!.details).toEqual({ files: [IDENTITY_REL], embeddedKeyFields: { [IDENTITY_REL]: ['secretKey'] } });
      // The missing .gitignore is no longer a low advisory: a key is present.
      const git001 = findings.find((f) => f.checkId === 'GIT-001' && !f.passed);
      expect(git001?.severity).toBe('high');
    });

    it('catches a 32-byte key in a config file at any path', async () => {
      const findings = await scanTree({ 'deploy/signer.json': JSON.stringify({ privateKey: randomBytes(32).toString('hex') }) });
      const cred002 = findings.find((f) => f.checkId === 'CRED-002' && !f.passed);
      expect(cred002?.file).toBe(path.join('deploy', 'signer.json'));
    });

    it('stays clean for an identity whose secretKey is a placeholder, and for public material', async () => {
      const findings = await scanTree({
        [IDENTITY_REL]: aimIdentity('FAKE-PLACEHOLDER'),
        'keys/public.json': JSON.stringify({ publicKey: randomBytes(32).toString('base64') }),
      });
      expect(findings.find((f) => f.checkId === 'CRED-002' && !f.passed)).toBeUndefined();
      // No key counted, so the missing .gitignore stays a low advisory.
      expect(findings.find((f) => f.checkId === 'GIT-001' && !f.passed)?.severity).toBe('low');
    });
  });
});
