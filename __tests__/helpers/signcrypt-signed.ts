/**
 * Really signed signcrypt fixtures.
 *
 * SKILL-001, HEARTBEAT-003 and the signcrypt plugin read a file as signed only
 * when its signcrypt block verifies under the signer key it names (#269). A
 * fixture that needs a signed file therefore has to sign it: a marker string
 * is exactly what those checks now reject.
 *
 * Two ways in. `signingPlugin()` is the real path — an aim-core identity
 * created in a temp directory, handed to the signcrypt plugin. `signcryptSigned()`
 * produces the same block as a pure function, for fixtures that are computed
 * as strings. Its key is derived from a fixed label, and Ed25519 signatures
 * are deterministic, so signing one body twice gives identical bytes: the
 * HMA-07 twin suites compare copies byte for byte.
 */
import * as crypto from 'node:crypto';
import { AIMCore, sign } from '@opena2a/aim-core';
import { SignCryptPlugin } from '../../src/plugins/signcrypt';
import { buildSigncryptBlock, sha256Hex } from '../../src/plugins/signcrypt-block';
import { tempDir } from './temp-dir';

/** DER header of a PKCS#8 Ed25519 private key; the 32-byte seed follows it. */
const PKCS8_ED25519_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');

export interface TestSigner {
  /** Base64, as the block's `signer` field carries it. */
  publicKey: string;
  /** The 64-byte seed-plus-public-key form aim-core's `sign` takes. */
  secretKey: Uint8Array;
}

export function testSigner(label = 'hackmyagent-test-signer'): TestSigner {
  const seed = crypto.createHash('sha256').update(label).digest();
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_HEADER, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const publicKey = spki.subarray(spki.length - 32);
  return { publicKey: publicKey.toString('base64'), secretKey: Buffer.concat([seed, publicKey]) };
}

/** `body` followed by a signcrypt block that verifies over it. */
export function signcryptSigned(body: string, signer: TestSigner = testSigner()): string {
  const hash = sha256Hex(body);
  const signature = sign(Buffer.from(hash, 'hex'), signer.secretKey);
  return body + buildSigncryptBlock({
    hash,
    signatureHex: Buffer.from(signature).toString('hex'),
    signerKey: signer.publicKey,
    signedAt: '2026-08-30T00:00:00.000Z',
    expiresAt: '2026-09-06T00:00:00.000Z',
  });
}

/**
 * The signcrypt plugin holding an aim-core identity generated for this test.
 * The identity lives in `dataDir`, outside any scanned tree; `tempDir` removes
 * it when the calling test finishes.
 */
export async function signingPlugin(): Promise<{ plugin: SignCryptPlugin; publicKey: string; dataDir: string }> {
  const dataDir = tempDir('hma-signer-');
  const aimCore = new AIMCore({ agentName: 'hma-test', dataDir });
  const plugin = new SignCryptPlugin();
  await plugin.init({ aimCore });
  return { plugin, publicKey: aimCore.getIdentity().publicKey, dataDir };
}
