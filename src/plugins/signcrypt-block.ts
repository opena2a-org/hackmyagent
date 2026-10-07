/**
 * The signcrypt signature block: its one writer and its one verifier.
 *
 * SKILL-001 and HEARTBEAT-003 in the static scanner and the signcrypt plugin's
 * own scan all decide "is this file signed" here, so the three can never
 * disagree. A file is signed only when it ends in a complete block whose
 * `pinned_hash` is the sha256 of the bytes before the block and whose
 * `opena2a_signature` is an Ed25519 signature over that hash, verifying under
 * the block's own `signer` key.
 *
 * Everything else is unsigned, however signature-like it looks: a bare
 * `opena2a_signature:` field, `opena2a_signature: unsigned`, an
 * `opena2a-guard hash=` digest a file carries of itself, a `BEGIN SIGNATURE`
 * line, or a block whose hash no longer matches the content. A hash a file
 * carries of itself proves nothing about who wrote it: anyone who edits the
 * file can recompute it. Only a signature that verifies under a key does.
 */
import { verify } from '@opena2a/aim-core';
import * as crypto from 'crypto';

export const SIGNCRYPT_OPEN = '<!-- opena2a:signcrypt -->';
export const SIGNCRYPT_CLOSE = '<!-- /opena2a:signcrypt -->';

/** The `---` line the writer puts between the content and the block. */
const SEPARATOR = '\n---\n';

const PINNED_HASH = /^sha256:([0-9a-f]{64})$/;
/** An Ed25519 signature is 64 bytes. */
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;
/** An Ed25519 public key is 32 bytes: 43 base64 characters and one pad. */
const SIGNER_BASE64 = /^[A-Za-z0-9+/]{43}=$/;

export interface SigncryptBlockFields {
  /** Hex sha256 of the content the block follows. */
  hash: string;
  /** Hex Ed25519 signature over the hash bytes, or `unsigned`. */
  signatureHex: string;
  /** Base64 Ed25519 public key, or `none`. */
  signerKey: string;
  signedAt: string;
  expiresAt: string;
}

/**
 * Why a file did not verify. `unverified` means the block's hash still
 * matches the content but no signature verifies over it: the file is pinned,
 * not signed.
 */
export type UnsignedReason =
  | 'no-block'
  | 'incomplete-block'
  | 'content-after-block'
  | 'malformed-block'
  | 'hash-mismatch'
  | 'unverified';

export type SignatureVerdict =
  | { signed: true; signer: string; hash: string }
  | { signed: false; reason: UnsignedReason };

/** The block exactly as the signcrypt writer appends it, separator first. */
export function buildSigncryptBlock(fields: SigncryptBlockFields): string {
  return [
    '',
    '---',
    SIGNCRYPT_OPEN,
    `pinned_hash: sha256:${fields.hash}`,
    `opena2a_signature: ${fields.signatureHex}`,
    `signer: ${fields.signerKey}`,
    `signed_at: ${fields.signedAt}`,
    `expires_at: ${fields.expiresAt}`,
    SIGNCRYPT_CLOSE,
  ].join('\n') + '\n';
}

interface LocatedBlock {
  /** The bytes the block covers: everything before it, separator excluded. */
  body: string;
  /** The text between the open and close markers. */
  inner: string;
}

/** The last block in the file, and the content it covers. */
function locateBlock(content: string): LocatedBlock | UnsignedReason {
  const open = content.lastIndexOf(SIGNCRYPT_OPEN);
  if (open === -1) return 'no-block';
  const close = content.indexOf(SIGNCRYPT_CLOSE, open + SIGNCRYPT_OPEN.length);
  if (close === -1) return 'incomplete-block';
  // Anything after the block is content the signature does not cover.
  if (!/^\s*$/.test(content.slice(close + SIGNCRYPT_CLOSE.length))) return 'content-after-block';
  const before = content.slice(0, open);
  return {
    body: before.endsWith(SEPARATOR) ? before.slice(0, -SEPARATOR.length) : before,
    inner: content.slice(open + SIGNCRYPT_OPEN.length, close),
  };
}

/** The content with a trailing signcrypt block removed, for re-signing. */
export function stripSigncryptBlock(content: string): string {
  const located = locateBlock(content);
  return typeof located === 'string' ? content : located.body;
}

export function sha256Hex(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function verifySigncryptSignature(content: string): SignatureVerdict {
  const located = locateBlock(content);
  if (typeof located === 'string') return { signed: false, reason: located };

  const fields = new Map<string, string>();
  for (const raw of located.inner.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon <= 0) return { signed: false, reason: 'malformed-block' };
    const key = line.slice(0, colon);
    // A repeated field leaves two readings of one block; take neither.
    if (fields.has(key)) return { signed: false, reason: 'malformed-block' };
    fields.set(key, line.slice(colon + 1).trim());
  }

  const pinned = PINNED_HASH.exec(fields.get('pinned_hash') ?? '');
  if (!pinned) return { signed: false, reason: 'malformed-block' };
  const hash = pinned[1];
  if (sha256Hex(located.body) !== hash) return { signed: false, reason: 'hash-mismatch' };

  const signatureHex = fields.get('opena2a_signature') ?? '';
  const signer = fields.get('signer') ?? '';
  if (!SIGNATURE_HEX.test(signatureHex) || !SIGNER_BASE64.test(signer)) {
    return { signed: false, reason: 'unverified' };
  }
  const publicKey = Buffer.from(signer, 'base64');
  if (publicKey.length !== 32) return { signed: false, reason: 'unverified' };
  let ok = false;
  try {
    ok = verify(Buffer.from(hash, 'hex'), Buffer.from(signatureHex, 'hex'), publicKey);
  } catch {
    ok = false;
  }
  return ok ? { signed: true, signer, hash } : { signed: false, reason: 'unverified' };
}

/** One clause for a finding message: why a file reads as unsigned. */
export function describeUnsigned(reason: UnsignedReason): string {
  switch (reason) {
    case 'no-block':
      return 'no signcrypt signature block';
    case 'incomplete-block':
      return 'the signcrypt signature block is not closed';
    case 'content-after-block':
      return 'content follows the signcrypt signature block, so the signature does not cover it';
    case 'malformed-block':
      return 'the signcrypt signature block is malformed';
    case 'hash-mismatch':
      return 'the file changed after it was signed';
    case 'unverified':
      return 'the signcrypt block pins a hash but carries no signature that verifies under its signer key';
  }
}
