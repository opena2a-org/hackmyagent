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
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';
import { TMEClassifier, isAllowedModelHost } from '../../src/nanomind-core/inference/tme-classifier';
import { orchestrateNanoMind } from '../../src/nanomind-core/orchestrate';

// The pinned sizes, from the files at the pinned commit (their sha256 values
// match the pins in tme-classifier.ts).
const TOKENIZER_BYTES = 168_639;
const ONNX_BYTES = 142_990;
const ONNX_DATA_BYTES = 8_380_416;

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
    writeFileSync(join(dir, 'tokenizer.json'), '{}');
    failFetch();

    await TMEClassifier.downloadModel(dir);

    const expected = ((ONNX_BYTES + ONNX_DATA_BYTES) / 1_000_000).toFixed(1);
    expect(stderr[0]).toContain(`(2 file(s), ${expected} MB)`);
  });

  it('writes nothing and makes no request when every file is cached', async () => {
    for (const name of ['tokenizer.json', 'nanomind-tme.onnx', 'nanomind-tme.onnx.data']) {
      writeFileSync(join(dir, name), '');
    }
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
