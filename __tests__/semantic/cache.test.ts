import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LLMCache, layer3CacheDir } from '../../src/semantic/llm/cache';
import { projectKey } from '../../src/store/project-store';
import { tempDir } from '../helpers/temp-dir';
import * as fs from 'fs/promises';
import { existsSync, readdirSync, realpathSync } from 'fs';
import * as path from 'path';
import * as os from 'os';
import { randomUUID } from 'crypto';

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

  it('writes a finding through the credential redaction, keeping the finding', async () => {
    // Built at run time, so no credential-shaped literal sits in this file.
    const canary = `canary-${randomUUID()}`;
    const hash = cache.hash('the scanned file', 'prompt');
    await cache.set(hash, {
      hash,
      findings: [{
        id: 'SEM-LLM-001',
        title: 'Hardcoded credential',
        description: `The config sets api_token=${canary}`,
        rationale: `db_password: ${canary} is stored in plain text`,
        category: 'credential',
        severity: 'high',
        file: 'CLAUDE.md',
        line: 3,
        recommendation: 'Move the value to an environment variable.',
        layer: 3,
        autoFixable: false,
      }],
      model: 'haiku',
      timestamp: new Date().toISOString(),
      inputTokens: 100,
      outputTokens: 50,
    });

    const written = await fs.readFile(path.join(tempDir, `${hash}.json`), 'utf-8');
    expect(written.includes(canary), 'the cache entry holds the credential value its finding quoted').toBe(false);
    const stored = (await cache.get(hash))!;
    expect(stored.findings).toHaveLength(1);
    expect(stored.findings[0].title).toBe('Hardcoded credential');
    expect(stored.findings[0].description).toBe('The config sets api_token=[REDACTED]');
    expect(stored.findings[0].rationale).toBe('db_password: [REDACTED] is stored in plain text');
  });
});

describe('where the Layer 3 cache lives', () => {
  let root: string;
  let home: string;

  beforeEach(() => {
    root = realpathSync(tempDir('hma-cache-location-'));
    home = path.join(root, 'home');
    vi.stubEnv('OPENA2A_HOME', home);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  async function tree(name: string): Promise<string> {
    const dir = path.join(root, name);
    await fs.mkdir(dir);
    return dir;
  }

  it('is the llm-cache directory of the scanned tree\'s user store, outside the tree', async () => {
    const a = await tree('a');
    const dir = layer3CacheDir(a);
    expect(dir).toBe(path.join(home, 'projects', projectKey(realpathSync.native(a)), 'llm-cache'));
    expect(path.relative(a, dir!).startsWith('..')).toBe(true);
  });

  it('gives two scanned trees two directories', async () => {
    expect(layer3CacheDir(await tree('a'))).not.toBe(layer3CacheDir(await tree('b')));
  });

  it('is null, so nothing is kept, when the user store would sit inside the scanned tree', async () => {
    const a = await tree('a');
    vi.stubEnv('OPENA2A_HOME', path.join(a, '.opena2a'));
    expect(layer3CacheDir(a)).toBeNull();

    const cache = new LLMCache(null);
    const hash = cache.hash('content', 'prompt');
    await cache.set(hash, { hash, findings: [], model: 'haiku', timestamp: '', inputTokens: 1, outputTokens: 1 });
    expect(await cache.get(hash)).toBeNull();
    expect(readdirSync(a)).toEqual([]);
  });

  it('defaults to the state directory of the working directory\'s tree, writing nothing in it', async () => {
    const cwd = await tree('cwd');
    vi.spyOn(process, 'cwd').mockReturnValue(cwd);
    const cache = new LLMCache();
    const hash = cache.hash('content', 'prompt');
    await cache.set(hash, { hash, findings: [], model: 'haiku', timestamp: '', inputTokens: 1, outputTokens: 1 });

    expect(readdirSync(cwd)).toEqual([]);
    expect(existsSync(path.join(layer3CacheDir(cwd)!, `${hash}.json`))).toBe(true);
  });
});
