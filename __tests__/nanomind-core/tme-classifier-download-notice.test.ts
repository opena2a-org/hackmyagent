/**
 * A first run that downloads the NanoMind classifier says so on stderr before
 * the first request, in every output mode.
 *
 * `secure --json` on an empty HOME used to fetch the model files from
 * Hugging Face with nothing on either stream: the only notice was gated on
 * the same `silent` flag every machine format sets, and its size was a stale
 * literal. The notice now lives in `downloadModel`, where the request is
 * made, takes no quiet switch, states the size the pinned per-file byte
 * counts add up to, and is followed by exactly one outcome line. Redirects
 * are followed only to the hosts the notice names.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import https from 'node:https';
import { TMEClassifier, isAllowedModelHost } from '../../src/nanomind-core/inference/tme-classifier';
import { orchestrateNanoMind } from '../../src/nanomind-core/orchestrate';

// The pinned sizes, from the files at the pinned commit (their sha256 values
// match the pins in tme-classifier.ts).
const TOKENIZER_BYTES = 168_639;
const ONNX_BYTES = 142_990;
const ONNX_DATA_BYTES = 8_380_416;
const PINNED_SHA256: Record<string, string> = {
  'tokenizer.json': '5ace7e6441505cf24dfb84d10b237c66edccaece075b3c5b0736c007d65355ce',
  'nanomind-tme.onnx': '1c9c6db00385e0e871ee6d2508d90a3210eddd4abf45365151fb859d8abab9eb',
  'nanomind-tme.onnx.data': '1367c0d3086b8d5c698dc37ae309c3afdb41ffa4d35ecac9b8f1882ffeb1d018',
};

/**
 * A model cache in `dir` holding every file at its pinned size, or at the
 * size `sizes` gives for it. The content is zeros, so a test that needs the
 * cache trusted also calls `hashAsPinned`.
 */
function writeCache(dir: string, sizes: Record<string, number> = {}): void {
  const pinned: Record<string, number> = {
    'tokenizer.json': TOKENIZER_BYTES,
    'nanomind-tme.onnx': ONNX_BYTES,
    'nanomind-tme.onnx.data': ONNX_DATA_BYTES,
  };
  for (const [name, bytes] of Object.entries(pinned)) {
    writeFileSync(join(dir, name), Buffer.alloc(sizes[name] ?? bytes));
  }
}

/**
 * Make the cache check read each model file's sha256 as its pinned value,
 * except for the files named in `altered`, which read as some other value.
 */
function hashAsPinned(altered: string[] = []) {
  return vi.spyOn(TMEClassifier as any, 'hashFileSync').mockImplementation((path: unknown) => {
    const name = basename(String(path));
    return altered.includes(name) ? '0'.repeat(64) : PINNED_SHA256[name];
  });
}

describe('NanoMind model download notice', () => {
  let dir: string;
  let events: string[];
  let stderr: string[];
  let stdout: string[];

  beforeEach(() => {
    // A proxy variable in the developer's shell would send these requests
    // through a tunnel instead of the direct `https.get` call the
    // redirect test stubs. model-download-proxy.test.ts covers proxies.
    for (const name of ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY']) {
      vi.stubEnv(name, '');
    }
    dir = mkdtempSync(join(tmpdir(), 'hma-model-notice-'));
    events = [];
    stderr = [];
    stdout = [];
    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => {
      stderr.push(String(chunk));
      events.push('stderr');
      return true;
    }) as typeof process.stderr.write);
    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
      stdout.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    rmSync(dir, { recursive: true, force: true });
  });

  const failFetch = () =>
    vi.spyOn(TMEClassifier as any, 'downloadFile').mockImplementation(async () => {
      events.push('request');
      throw new Error('getaddrinfo ENOTFOUND huggingface.co');
    });

  it('writes the notice to stderr before the first request, naming hosts, size, cache path and the opt-out', async () => {
    failFetch();

    const ok = await TMEClassifier.downloadModel(dir, { optOut: '--static-only' });

    expect(ok).toBe(false);
    expect(events.indexOf('stderr')).toBeGreaterThanOrEqual(0);
    expect(events.indexOf('stderr')).toBeLessThan(events.indexOf('request'));
    const notice = stderr.slice(0, 2).join('');
    expect(notice).toContain("huggingface.co and Hugging Face's content CDN");
    const all = ((TOKENIZER_BYTES + ONNX_BYTES + ONNX_DATA_BYTES) / 1_000_000).toFixed(1);
    expect(notice).toContain(`(3 file(s), ${all} MB)`);
    expect(notice).toContain(dir);
    expect(notice).toContain('once per cache');
    expect(notice).toContain('run this command with --static-only');
    // The notice names the stable host set, never a regional CDN host.
    expect(notice).not.toMatch(/cdn\.hf\.co/);
    expect(stdout).toEqual([]);
  });

  it('follows the notice with exactly one failure line saying the classifier did not run', async () => {
    failFetch();

    await TMEClassifier.downloadModel(dir);

    expect(stderr).toHaveLength(3);
    expect(stderr[2]).toContain('NanoMind: model download failed: tokenizer.json: getaddrinfo ENOTFOUND huggingface.co.');
    expect(stderr[2]).toContain('The classifier did not run');
    expect(stderr[2]).toContain('results can differ');
  });

  it('names no flag when the command registers none', async () => {
    failFetch();

    await TMEClassifier.downloadModel(dir);

    expect(stderr.join('')).not.toContain('To skip it');
  });

  it('states the size of only the files it is about to fetch', async () => {
    writeFileSync(join(dir, 'tokenizer.json'), Buffer.alloc(TOKENIZER_BYTES));
    hashAsPinned();
    failFetch();

    await TMEClassifier.downloadModel(dir);

    const expected = ((ONNX_BYTES + ONNX_DATA_BYTES) / 1_000_000).toFixed(1);
    expect(stderr[0]).toContain(`(2 file(s), ${expected} MB)`);
  });

  it('writes nothing and makes no request when every file is cached', async () => {
    writeCache(dir);
    hashAsPinned();
    const fetch = failFetch();

    expect(await TMEClassifier.downloadModel(dir)).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
    expect(stderr).toEqual([]);
  });

  it('rejects a file whose size differs from its pinned byte count, before hashing it', async () => {
    vi.spyOn(TMEClassifier as any, 'downloadFile').mockImplementation(async (_url: unknown, dest: unknown) => {
      writeFileSync(String(dest), 'x'.repeat(10));
    });
    const hash = vi.spyOn(TMEClassifier as any, 'computeHash');

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);
    expect(hash).not.toHaveBeenCalled();
    expect(existsSync(join(dir, 'tokenizer.json'))).toBe(false);
    expect(stderr[2]).toContain(`tokenizer.json: received 10 bytes, expected ${TOKENIZER_BYTES}`);
  });

  it('rejects a file of the pinned size whose sha256 differs, and removes it', async () => {
    vi.spyOn(TMEClassifier as any, 'downloadFile').mockImplementation(async (_url: unknown, dest: unknown) => {
      writeFileSync(String(dest), Buffer.alloc(TOKENIZER_BYTES));
    });
    const hash = vi.spyOn(TMEClassifier as any, 'computeHash');

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);
    expect(hash).toHaveBeenCalledTimes(1);
    expect(existsSync(join(dir, 'tokenizer.json'))).toBe(false);
    expect(stderr).toHaveLength(3);
    expect(stderr[2]).toContain('NanoMind: model download failed: tokenizer.json: sha256 does not match the pinned value.');
    expect(stderr[2]).toContain('The classifier did not run');
  });

  it('downloads again a cached file whose size differs from its pinned byte count', async () => {
    // A process killed part-way through a write leaves a short file behind.
    writeCache(dir, { 'nanomind-tme.onnx.data': 4096 });
    hashAsPinned();
    const urls: string[] = [];
    vi.spyOn(TMEClassifier as any, 'downloadFile').mockImplementation(async (url: unknown) => {
      urls.push(String(url));
      throw new Error('getaddrinfo ENOTFOUND huggingface.co');
    });

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toMatch(/\/nanomind-tme\.onnx\.data$/);
    expect(stderr[0]).toContain(`(1 file(s), ${(ONNX_DATA_BYTES / 1_000_000).toFixed(1)} MB)`);
  });

  it('downloads again a cached file of the pinned size whose sha256 differs', async () => {
    writeCache(dir);
    hashAsPinned(['nanomind-tme.onnx.data']);
    const urls: string[] = [];
    vi.spyOn(TMEClassifier as any, 'downloadFile').mockImplementation(async (url: unknown) => {
      urls.push(String(url));
      throw new Error('getaddrinfo ENOTFOUND huggingface.co');
    });

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toMatch(/\/nanomind-tme\.onnx\.data$/);
  });

  // The cache check in the constructor: a tokenizer that matches its pin
  // used to make every other cached file count as good, so a truncated
  // weights file was loaded on every run, with no download and no notice.
  it('a scan downloads again when a cached file is shorter than its pinned size', async () => {
    writeCache(dir, { 'nanomind-tme.onnx.data': 4096 });
    hashAsPinned();
    const download = vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);

    await new TMEClassifier(dir).ensureModel();

    expect(download).toHaveBeenCalledTimes(1);
  });

  it('a scan uses the cache as is when every cached file has its pinned size and sha256', async () => {
    writeCache(dir);
    hashAsPinned();
    const download = vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);

    await new TMEClassifier(dir).ensureModel();

    expect(download).not.toHaveBeenCalled();
  });

  // A pinned tokenizer used to vouch for the weights beside it, so weights of
  // the pinned sizes and any content were loaded with no download.
  it.each(['nanomind-tme.onnx', 'nanomind-tme.onnx.data'])(
    'a scan downloads again when cached %s has its pinned size and another sha256',
    async (name) => {
      writeCache(dir);
      hashAsPinned([name]);
      const download = vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);

      await new TMEClassifier(dir).ensureModel();

      expect(download).toHaveBeenCalledTimes(1);
    },
  );

  it('loads no model files from ./models in the working directory', () => {
    mkdirSync(join(dir, 'models'));
    writeCache(join(dir, 'models'));
    hashAsPinned();
    vi.spyOn(process, 'cwd').mockReturnValue(dir);

    const classifier = new TMEClassifier() as any;

    expect(classifier.modelPath.startsWith(dir)).toBe(false);
    expect(classifier.tokenizerPath.startsWith(dir)).toBe(false);
  });

  it('refuses a redirect to a host outside huggingface.co and *.hf.co, without requesting it', async () => {
    const requested: string[] = [];
    vi.spyOn(https, 'get').mockImplementation(((url: unknown, _opts: unknown, cb: (res: unknown) => void) => {
      requested.push(String(url));
      const res = Object.assign(new PassThrough(), {
        statusCode: 302,
        headers: { location: 'https://downloads.example.com/nanomind-tme.onnx' },
      });
      process.nextTick(() => cb(res));
      return new EventEmitter();
    }) as unknown as typeof https.get);

    expect(await TMEClassifier.downloadModel(dir)).toBe(false);
    expect(requested).toHaveLength(1);
    expect(new URL(requested[0]).host).toBe('huggingface.co');
    expect(stderr[2]).toContain('refused a request to downloads.example.com');
  });
});

describe('model download host allowlist', () => {
  it.each([
    ['https://huggingface.co/opena2a/nanomind-security-classifier/resolve/x/tokenizer.json', true],
    ['https://us.aws.cdn.hf.co/xet-bridge/abc', true],
    ['https://cas-bridge.xethub.hf.co/abc', true],
    ['https://cdn-lfs.huggingface.co/x', true],
    ['https://cdn-lfs.us-1.huggingface.co/x', true],
    ['https://evilhuggingface.co/x', false],
    ['http://cdn-lfs.huggingface.co/x', false],
    ['http://huggingface.co/x', false],
    ['https://evilhf.co/x', false],
    ['https://huggingface.co.example.com/x', false],
    ['https://hf.co.example.com/x', false],
    ['not a url', false],
  ])('%s -> %s', (url, allowed) => {
    expect(isAllowedModelHost(url)).toBe(allowed);
  });
});

describe('secure --static-only, the flag the notice names', () => {
  afterEach(() => vi.restoreAllMocks());

  it('reaches no model download and no network request', async () => {
    const download = vi.spyOn(TMEClassifier, 'downloadModel');
    const ensure = vi.spyOn(TMEClassifier.prototype, 'ensureModel');
    const get = vi.spyOn(https, 'get');
    const dir = mkdtempSync(join(tmpdir(), 'hma-static-only-'));
    try {
      const result = await orchestrateNanoMind(dir, [], { staticOnly: true, modelDownloadOptOut: '--static-only' });
      expect(result.nanomindUsed).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    expect(download).not.toHaveBeenCalled();
    expect(ensure).not.toHaveBeenCalled();
    expect(get).not.toHaveBeenCalled();
  });
});
