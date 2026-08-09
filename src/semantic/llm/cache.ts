/**
 * LLM Response Cache (Layer 3)
 *
 * SHA-256 content-hash based cache. Same file content = same analysis result.
 * Stored in .hackmyagent-cache/ (or configurable directory).
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

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
  private cacheDir: string;

  constructor(cacheDir: string = '.hackmyagent-cache') {
    this.cacheDir = cacheDir;
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
    const cachePath = path.join(this.cacheDir, `${contentHash}.json`);
    try {
      const data = await fs.readFile(cachePath, 'utf-8');
      return JSON.parse(data) as CacheEntry;
    } catch {
      return null;
    }
  }

  /**
   * Store response in cache.
   */
  async set(contentHash: string, entry: CacheEntry): Promise<void> {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      const cachePath = path.join(this.cacheDir, `${contentHash}.json`);
      await fs.writeFile(cachePath, JSON.stringify(entry, null, 2));
    } catch {
      // Cache write failures are non-fatal
    }
  }

  /**
   * Check if a hash has a cached result.
   */
  async has(contentHash: string): Promise<boolean> {
    const cachePath = path.join(this.cacheDir, `${contentHash}.json`);
    try {
      await fs.access(cachePath);
      return true;
    } catch {
      return false;
    }
  }
}
