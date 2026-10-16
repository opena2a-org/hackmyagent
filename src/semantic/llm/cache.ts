/**
 * LLM Response Cache (Layer 3)
 *
 * SHA-256 content-hash based cache. Same file content = same analysis result.
 * Stored in the state directory of the scanned tree (`layer3CacheDir`), never
 * inside that tree, and every finding text passes through the credential
 * redaction before it is written.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { redactTargetArtifact } from '../../attack-engine/target-reader';
import { resolveProjectStore } from '../../store/project-store';

/** The directory of a tree's user store that holds Layer 3's cache and budget record. */
const LAYER3_STORE_DIR = 'llm-cache';

/**
 * Where Layer 3 keeps its cache and budget record for the tree rooted at
 * `scanRoot`: `$OPENA2A_HOME/projects/<key>/llm-cache`, the user store the CLI
 * keeps for that tree (src/store/project-store.ts). The resolver refuses a
 * store inside the scanned tree, so a broad `git add` in the scanned
 * repository cannot commit it, and the key is the tree's real path, so two
 * trees never share an entry. `null` when that store would sit inside the
 * tree (a scan of a tree that holds `$OPENA2A_HOME`) or the tree cannot be
 * resolved: Layer 3 then keeps nothing between runs.
 */
export function layer3CacheDir(scanRoot: string): string | null {
  try {
    return resolveProjectStore(scanRoot).dirFor(LAYER3_STORE_DIR);
  } catch {
    return null;
  }
}

/**
 * Create `dir` private to the user: every directory this creates on the way,
 * the store's own root included, is 0700.
 */
export async function ensurePrivateDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
}

/**
 * Every string in `value` through `redactTargetArtifact`, the redaction the
 * behavioural simulation applies to what it sends. A finding can quote the
 * line it is about, credential value included, and the cache keeps it at
 * rest. The redaction replaces the values it recognises, such as the value
 * after a credential-named key or the password in a URL; a value quoted with
 * nothing that marks it as a credential is kept as written.
 */
function redactForStorage<T>(value: T): T {
  if (typeof value === 'string') return redactTargetArtifact(value).text as T;
  if (Array.isArray(value)) return value.map(redactForStorage) as T;
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, redactForStorage(v)]),
    ) as T;
  }
  return value;
}

export interface CacheEntry {
  hash: string;
  /**
   * #462 — the PARSED result, not the raw response text.
   *
   * The raw text used to be written before the parse and re-parsed on every
   * later run, so a response HMA could not read was replayed forever: one
   * poisoned answer suppressed that file's findings on every subsequent scan, at
   * no API cost, printing `(cached)`. A response that cannot be parsed now
   * produces no cache entry at all.
   */
  findings: import('../types').SemanticFinding[];
  model: string;
  timestamp: string;
  inputTokens: number;
  outputTokens: number;
}

export class LLMCache {
  private cacheDir: string | null;

  /**
   * `cacheDir` is the directory to use. Left out, it is the state directory of
   * the working directory's tree (`layer3CacheDir`); `null` keeps nothing.
   */
  constructor(cacheDir?: string | null) {
    this.cacheDir = cacheDir === undefined ? layer3CacheDir(process.cwd()) : cacheDir;
  }

  /**
   * Generate SHA-256 hash of content + prompt (so different analysis types
   * don't share cache entries).
   */
  hash(content: string, systemPrompt: string): string {
    return crypto
      .createHash('sha256')
      .update(content)
      .update('\0')
      .update(systemPrompt)
      .digest('hex');
  }

  /**
   * Get cached response for content hash. Returns null if not cached.
   */
  async get(contentHash: string): Promise<CacheEntry | null> {
    if (this.cacheDir === null) return null;
    const cachePath = path.join(this.cacheDir, `${contentHash}.json`);
    try {
      const data = await fs.readFile(cachePath, 'utf-8');
      return JSON.parse(data) as CacheEntry;
    } catch {
      return null;
    }
  }

  /**
   * Store response in cache, its findings redacted.
   */
  async set(contentHash: string, entry: CacheEntry): Promise<void> {
    if (this.cacheDir === null) return;
    try {
      await ensurePrivateDir(this.cacheDir);
      const cachePath = path.join(this.cacheDir, `${contentHash}.json`);
      const stored: CacheEntry = { ...entry, findings: redactForStorage(entry.findings) };
      await fs.writeFile(cachePath, JSON.stringify(stored, null, 2), { mode: 0o600 });
    } catch {
      // Cache write failures are non-fatal
    }
  }

  /**
   * Check if a hash has a cached result.
   */
  async has(contentHash: string): Promise<boolean> {
    if (this.cacheDir === null) return false;
    const cachePath = path.join(this.cacheDir, `${contentHash}.json`);
    try {
      await fs.access(cachePath);
      return true;
    } catch {
      return false;
    }
  }
}
