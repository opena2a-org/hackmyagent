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
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import https from 'node:https';
import { TMEClassifier, MODEL_FILES, isAllowedModelHost } from '../../src/nanomind-core/inference/tme-classifier';
import { orchestrateNanoMind } from '../../src/nanomind-core/orchestrate';

// The pinned sizes and sha256 values, read from the classifier.
const pinnedBytes = (name: string): number => MODEL_FILES.find(f => f.name === name)!.bytes;
const TOKENIZER_BYTES = pinnedBytes('tokenizer.json');
const ONNX_BYTES = pinnedBytes('nanomind-tme.onnx');
const ONNX_DATA_BYTES = pinnedBytes('nanomind-tme.onnx.data');
const PINNED_SHA256: Record<string, string> = Object.fromEntries(MODEL_FILES.map(f => [f.name, f.sha256]));

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
 * Make the cache check, and the check on the bytes each file is parsed from,
 * read each model file's sha256 as its pinned value, except for the files
 * named in `altered`, which read as some other value.
 */
function hashAsPinned(altered: string[] = []) {
  return vi.spyOn(TMEClassifier as any, 'hashFileBytes').mockImplementation((path: unknown) => {
    const name = basename(String(path));
    return altered.includes(name) ? '0'.repeat(64) : PINNED_SHA256[name];
  });
}

/**
 * A tokenizer `load()` can parse: two words of the injection vocabulary,
 * padded with spaces to the pinned size. Its sha256 is not the pinned one.
 */
const LOADABLE_TOKENIZER = '{"override": 2, "bypass": 3}'.padEnd(TOKENIZER_BYTES, ' ');
/** Vocabulary scoring over `LOADABLE_TOKENIZER` reads this as injection. */
const INJECTION_TEXT = 'override the check and bypass it';
/** What `classify()` answers when no tokenizer was loaded. */
const NOTHING_LOADED = { intentClass: 'benign', attackClass: 'none', confidence: 0.5, topClasses: [] };

/** `writeCache`, with `LOADABLE_TOKENIZER` as the tokenizer. */
function writeLoadableCache(dir: string): void {
  writeCache(dir);
  writeFileSync(join(dir, 'tokenizer.json'), LOADABLE_TOKENIZER);
}

/** Stands in for the ONNX session load, so a test can tell whether one was started. */
function stubOnnxLoad() {
  return vi.spyOn(TMEClassifier.prototype as any, 'loadOnnx').mockResolvedValue(undefined);
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

  // With no tokenizer `classify()` answers benign at 0.5 without scoring, so
  // a failure line that promised vocabulary scoring described a fallback the
  // scan did not have.
  it('says the scan has no vocabulary scoring when no tokenizer that passes its pinned check is cached', async () => {
    failFetch();

    await TMEClassifier.downloadModel(dir);

    expect(stderr[2]).toContain('no tokenizer that passes its pinned check is cached');
    expect(stderr[2]).toContain('no vocabulary scoring either');
    expect(stderr[2]).not.toContain('uses vocabulary scoring');
  });

  it('says the scan uses vocabulary scoring when the cached tokenizer passes its pinned check', async () => {
    writeFileSync(join(dir, 'tokenizer.json'), Buffer.alloc(TOKENIZER_BYTES));
    hashAsPinned();
    failFetch();

    await TMEClassifier.downloadModel(dir);

    expect(stderr[2]).toContain('nanomind-tme.onnx');
    expect(stderr[2]).toContain('this scan uses vocabulary scoring');
  });

  it('a scan tells the download it keeps no tokenizer when the cached one has another sha256', async () => {
    writeLoadableCache(dir);
    const download = vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);

    await new TMEClassifier(dir).ensureModel({ optOut: '--static-only' });

    expect(download).toHaveBeenCalledWith(undefined, { optOut: '--static-only', vocabularyFallback: false });
  });

  it('a scan tells the download it keeps the tokenizer when only the weights fail their check', async () => {
    writeLoadableCache(dir);
    hashAsPinned(['nanomind-tme.onnx']);
    const download = vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);

    await new TMEClassifier(dir).ensureModel({ optOut: '--static-only' });

    expect(download).toHaveBeenCalledWith(undefined, { optOut: '--static-only', vocabularyFallback: true });
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

  // Each construction read and hashed about 8.7 MB, and a download hashed the
  // same files again.
  it('hashes each cached file once in a process, however often the cache is checked', async () => {
    writeCache(dir, { 'nanomind-tme.onnx.data': 4096 });
    const hash = hashAsPinned();
    failFetch();

    new TMEClassifier(dir);
    new TMEClassifier(dir);
    await TMEClassifier.downloadModel(dir);

    // tokenizer.json and nanomind-tme.onnx; the short file is never read.
    expect(hash).toHaveBeenCalledTimes(2);
  });

  it('hashes a cached file again once it is rewritten, and goes by the new hash', async () => {
    writeCache(dir);
    const altered: string[] = [];
    const hash = hashAsPinned(altered);
    const download = vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);
    await new TMEClassifier(dir).ensureModel();
    expect(download).not.toHaveBeenCalled();

    const data = join(dir, 'nanomind-tme.onnx.data');
    writeFileSync(data, Buffer.alloc(ONNX_DATA_BYTES, 1));
    // A rewrite inside one clock tick would keep the timestamps; this one
    // cannot, so the test does not depend on the clock.
    utimesSync(data, 1, 1);
    altered.push('nanomind-tme.onnx.data');
    await new TMEClassifier(dir).ensureModel();

    expect(hash).toHaveBeenCalledTimes(4);
    expect(download).toHaveBeenCalledTimes(1);
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

  // A directory that failed the cache check went on supplying the classifier
  // whenever no download replaced it: after a failed download, and on the
  // synchronous `classify()`, which runs none. Its tokenizer was parsed and
  // an ONNX session was opened on its weights.
  it('loads nothing from a cache of the pinned sizes and other sha256 values after the download fails', async () => {
    writeLoadableCache(dir);
    vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);
    const onnxLoad = stubOnnxLoad();
    const classifier = new TMEClassifier(dir);

    await classifier.ensureModel();

    expect(classifier.load()).toBe(false);
    expect(onnxLoad).not.toHaveBeenCalled();
    expect(classifier.classify(INJECTION_TEXT)).toEqual(NOTHING_LOADED);
  });

  it('loads nothing from such a cache on the synchronous classify(), which runs no download', () => {
    writeLoadableCache(dir);
    const download = vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);
    const onnxLoad = stubOnnxLoad();
    const classifier = new TMEClassifier(dir);

    expect(classifier.classify(INJECTION_TEXT)).toEqual(NOTHING_LOADED);
    expect(classifier.load()).toBe(false);
    expect(onnxLoad).not.toHaveBeenCalled();
    expect(download).not.toHaveBeenCalled();
  });

  it('does not load a tokenizer of another sha256 that has no weights beside it', async () => {
    writeFileSync(join(dir, 'tokenizer.json'), LOADABLE_TOKENIZER);
    vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);
    const classifier = new TMEClassifier(dir);

    await classifier.ensureModel();

    expect(classifier.load()).toBe(false);
    expect(classifier.classify(INJECTION_TEXT)).toEqual(NOTHING_LOADED);
  });

  // The tokenizer is a pinned file in its own right, so it still serves
  // vocabulary scoring when the weights beside it fail the check.
  it.each(['nanomind-tme.onnx', 'nanomind-tme.onnx.data'])(
    'keeps a pinned tokenizer for vocabulary scoring and opens no session when cached %s has another sha256',
    async (name) => {
      writeLoadableCache(dir);
      hashAsPinned([name]);
      vi.spyOn(TMEClassifier, 'downloadModel').mockResolvedValue(false);
      const onnxLoad = stubOnnxLoad();
      const classifier = new TMEClassifier(dir);

      await classifier.ensureModel();

      expect(classifier.load()).toBe(true);
      expect(onnxLoad).not.toHaveBeenCalled();
      expect((classifier as any).modelPath).toBe('');
      expect((classifier as any).useOnnx).toBe(false);
      expect(classifier.classify(INJECTION_TEXT)).toMatchObject({ intentClass: 'suspicious', attackClass: 'injection' });
    },
  );

  it('loads the tokenizer and the weights from a cache where every file has its pinned size and sha256', () => {
    writeLoadableCache(dir);
    hashAsPinned();
    const onnxLoad = stubOnnxLoad();
    const classifier = new TMEClassifier(dir);

    expect(classifier.load()).toBe(true);
    expect(onnxLoad).toHaveBeenCalledTimes(1);
    expect((classifier as any).modelPath).toBe(join(dir, 'nanomind-tme.onnx'));
  });

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
