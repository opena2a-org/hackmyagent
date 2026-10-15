/**
 * #1047 — a PEM public key is not reported as a private key.
 *
 * The PEM private-key shape took one of `RSA `, `EC `, `DSA `, `OPENSSH `,
 * `ENCRYPTED ` or `PRIVATE` after `-----BEGIN `, then any run of capitals and
 * spaces before `KEY-----`, so nothing required the word PRIVATE. A config
 * holding an `RSA PUBLIC KEY` or `EC PUBLIC KEY` block was reported as
 * AST-CRED-003 "PEM private key", and `secure` scored it 69 and exited 1.
 *
 * The keys below are public keys generated per run; none is a secret. The
 * private control reuses the shared fixture's armor header and adds no
 * private-key line of its own.
 */

import { generateKeyPairSync } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';

import { scanCanonicalCredentialFormatsForTest } from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { SHAPE_FIXTURES } from '../helpers/credential-shape-fixtures';
import { tempDir } from '../helpers/temp-dir';

const PEM_LABEL = 'PEM private key';

/** A PKCS#1 RSA public key: its armor reads `RSA PUBLIC KEY`. */
function rsaPublicPem(): string {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return publicKey.export({ type: 'pkcs1', format: 'pem' }) as string;
}

/** An EC public key under the `EC PUBLIC KEY` armor some tools write. */
function ecPublicPem(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  return spki.replace(/PUBLIC KEY-----/g, 'EC PUBLIC KEY-----');
}

/** A YAML config holding `pem` as a block scalar; the armor header is on line 4. */
function configWith(pem: string): string {
  const block = pem.trimEnd().split('\n').map(l => `  ${l}`).join('\n');
  return ['service: verifier', 'issuer: example.org', 'public_key: |', block, ''].join('\n');
}

/** The same PEM with only its armor header replaced. */
function withHeader(pem: string, header: string): string {
  const lines = pem.trimEnd().split('\n');
  return [header, ...lines.slice(1), ''].join('\n');
}

async function credFindings(content: string) {
  const dir = tempDir('hma-pem-public-');
  await writeFile(join(dir, 'config.yaml'), content, 'utf-8');
  await writeFile(join(dir, 'README.md'), '# Verifier\n\nChecks signatures with the public key in config.yaml.\n', 'utf-8');
  const result = await runNanoMindScan(dir, []);
  return result.mergedFindings.filter(f => !f.passed && f.checkId === 'AST-CRED-003');
}

const rsaPublic = rsaPublicPem();
const ecPublic = ecPublicPem();
const privateHeader = SHAPE_FIXTURES['pem-private-key'].sample;

const PUBLIC_KEYS: Array<{ name: string; header: string; pem: string }> = [
  { name: 'RSA PUBLIC KEY', header: '-----B' + 'EGIN RSA PUBLIC KEY-----', pem: rsaPublic },
  { name: 'EC PUBLIC KEY', header: '-----B' + 'EGIN EC PUBLIC KEY-----', pem: ecPublic },
];

describe('#1047: a PEM public key is not a PEM private key', () => {
  it('the fixtures carry the armor headers they are named for', () => {
    for (const { header, pem } of PUBLIC_KEYS) expect(pem.split('\n')[0]).toBe(header);
  });

  for (const { name, pem } of PUBLIC_KEYS) {
    it(`an ${name} block in a config gives no PEM private key hit`, () => {
      const hits = scanCanonicalCredentialFormatsForTest(configWith(pem)).filter(h => h.label === PEM_LABEL);
      expect(hits).toEqual([]);
    });

    it(`an ${name} block in a config gives no AST-CRED-003`, async () => {
      expect(await credFindings(configWith(pem))).toEqual([]);
    });
  }

  it('control: the same config under the private-key armor header gives one hit and one AST-CRED-003', async () => {
    const content = configWith(withHeader(rsaPublic, privateHeader));
    const hits = scanCanonicalCredentialFormatsForTest(content).filter(h => h.label === PEM_LABEL);
    expect(hits).toHaveLength(1);

    const cred = await credFindings(content);
    expect(cred).toHaveLength(1);
    expect(cred[0].file).toBe('config.yaml');
    expect(cred[0].line).toBe(4);
    expect(cred[0].message).toBe(`Hardcoded secret: ${PEM_LABEL}: [REDACTED]`);
  });
});
