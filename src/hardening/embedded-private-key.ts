/**
 * A private key written as a VALUE inside a JSON document (#577).
 *
 * CRED-002 found a key written as a `.key` / `.pem` file and nothing else, so
 * the same key serialised into a JSON config was invisible: an Ed25519 signing
 * identity (`{"publicKey": "...", "secretKey": "<base64>"}`) scored 98/100 with
 * no credential finding. The file is `.json`, so the key-file branch never
 * looks at it, and the base64 value has no vendor prefix and carries `+` / `/`
 * / `=`, so the high-entropy credential patterns do not match it either.
 *
 * Both halves of the gate must hold, so a field that merely sounds secret is
 * not a key:
 *   - the field NAME denotes a private key: `privateKey`, `secretKey`, and
 *     their snake / kebab / any-case spellings;
 *   - the VALUE is raw key material: exactly 32 or 64 bytes written as base64
 *     (standard or url-safe, padded or not) or hex (optionally `0x`-prefixed).
 *     32 bytes is an Ed25519 / X25519 seed or a secp256k1 scalar; 64 is the
 *     seed-plus-public-key form that NaCl-family libraries call `secretKey`.
 * A decoded value with fewer than `MIN_DISTINCT_BYTES` distinct bytes is a
 * placeholder (`0x000…0`, a repeated pattern), not a key. A PEM block inside
 * JSON is out of scope here: the credential checks already report it in the
 * files they examine, and one key should not be reported twice.
 *
 * The file is identified by content, never by name, so the same detection
 * covers every tool that serialises a keypair to JSON.
 */

const PRIVATE_KEY_FIELD_NAMES = new Set(['privatekey', 'secretkey']);
const KEY_BYTE_LENGTHS = new Set([32, 64]);
const MIN_DISTINCT_BYTES = 16;
const MAX_DEPTH = 16;
const MAX_NODES = 10_000;

/** Cheap text pre-filter: no field spelled like a private-key name, no parse. */
export const PRIVATE_KEY_FIELD_HINT = /(?:private|secret)[_-]?key/i;

function isPrivateKeyFieldName(name: string): boolean {
  return PRIVATE_KEY_FIELD_NAMES.has(name.replace(/[_-]/g, '').toLowerCase());
}

function decodeKeyBytes(value: string): Buffer | null {
  const hex = value.replace(/^0x/i, '');
  if (/^[0-9a-fA-F]+$/.test(hex) && (hex.length === 64 || hex.length === 128)) {
    return Buffer.from(hex, 'hex');
  }
  const m = /^([A-Za-z0-9+/_-]+)(={0,2})$/.exec(value);
  if (!m) return null;
  const body = m[1];
  // Accept only the canonical length for each size, so a near-miss string
  // that a lenient decoder would truncate to 32 bytes does not count.
  for (const bytes of KEY_BYTE_LENGTHS) {
    const unpadded = Math.ceil((bytes * 4) / 3);
    const padded = Math.ceil(bytes / 3) * 4;
    if (body.length === unpadded && (m[2] === '' || body.length + m[2].length === padded)) {
      const decoded = Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      return decoded.length === bytes ? decoded : null;
    }
  }
  return null;
}

/** True when a JSON string value is private-key material by the rules above. */
export function isPrivateKeyValue(value: string): boolean {
  const bytes = decodeKeyBytes(value.trim());
  if (!bytes) return false;
  return new Set(bytes).size >= MIN_DISTINCT_BYTES;
}

/**
 * The names of the fields in a JSON document that hold a private key, at any
 * depth, deduplicated in document order. Empty for text that does not parse
 * and for a document with none. Only the field name is returned, never the
 * path to it: a name that passed the gate is letters, `_` and `-`, while a
 * parent key is arbitrary text from the scanned file. The walk is bounded in
 * depth and node count so a hostile document cannot stall the scan.
 */
export function privateKeyFieldsInJson(text: string): string[] {
  if (!PRIVATE_KEY_FIELD_HINT.test(text)) return [];
  let root: unknown;
  try {
    root = JSON.parse(text.replace(/^\uFEFF/, ''));
  } catch {
    return [];
  }
  const found = new Set<string>();
  let nodes = 0;
  const visit = (node: unknown, depth: number): void => {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (typeof value === 'string') {
        if (isPrivateKeyFieldName(key) && isPrivateKeyValue(value)) found.add(key);
      } else {
        visit(value, depth + 1);
      }
    }
  };
  visit(root, 0);
  return [...found];
}
