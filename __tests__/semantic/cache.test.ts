import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LLMCache } from '../../src/semantic/llm/cache';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

describe('LLMCache (file-based)', () => {
  let tempDir: string;
  let cache: LLMCache;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-cache-test-'));
    cache = new LLMCache(tempDir);
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('returns null for uncached hash', async () => {
    const result = await cache.get('nonexistent-hash');
    expect(result).toBeNull();
  });

  it('stores and retrieves cache entry', async () => {
    const hash = cache.hash('test content', 'test prompt');
    const entry = {
      hash,
      response: '[]',
      model: 'haiku',
      timestamp: new Date().toISOString(),
      inputTokens: 100,
      outputTokens: 50,
    };

    await cache.set(hash, entry);
    const result = await cache.get(hash);

    expect(result).not.toBeNull();
    expect(result!.hash).toBe(hash);
    expect(result!.response).toBe('[]');
    expect(result!.model).toBe('haiku');
  });

  it('has() returns true for cached entries', async () => {
    const hash = cache.hash('test', 'prompt');
    expect(await cache.has(hash)).toBe(false);

    await cache.set(hash, {
      hash,
      response: '[]',
      model: 'haiku',
      timestamp: new Date().toISOString(),
      inputTokens: 100,
      outputTokens: 50,
    });

    expect(await cache.has(hash)).toBe(true);
  });
});
