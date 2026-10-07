/**
 * The NanoMind classifier is downloaded from a fixed commit of the model
 * repository, not from its `main` branch.
 *
 * The download is checked against sha256 values pinned in the source. With a
 * `resolve/main` URL, any later commit to the model repository would change
 * what every install downloads, fail that check, and leave every scan on
 * vocabulary scoring without saying why. A commit URL keeps the files and the
 * pinned hashes describing the same bytes.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, posix } from 'node:path';
import { TMEClassifier } from '../../src/nanomind-core/inference/tme-classifier';

const MODEL_REPO = 'https://huggingface.co/opena2a/nanomind-security-classifier';
// A cached file counts only at its pinned size and sha256 (the values in
// tme-classifier.ts).
const PINNED_BYTES: Record<string, number> = {
  'tokenizer.json': 168_639,
  'nanomind-tme.onnx': 142_990,
  'nanomind-tme.onnx.data': 8_380_416,
};
const PINNED_SHA256: Record<string, string> = {
  'tokenizer.json': '5ace7e6441505cf24dfb84d10b237c66edccaece075b3c5b0736c007d65355ce',
  'nanomind-tme.onnx': '1c9c6db00385e0e871ee6d2508d90a3210eddd4abf45365151fb859d8abab9eb',
  'nanomind-tme.onnx.data': '1367c0d3086b8d5c698dc37ae309c3afdb41ffa4d35ecac9b8f1882ffeb1d018',
};

describe('NanoMind classifier download URL', () => {
  let dir: string;

  afterEach(() => {
    vi.restoreAllMocks();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('names a full commit sha for every model file', async () => {
    dir = mkdtempSync(join(tmpdir(), 'hma-model-pin-'));
    const urls: string[] = [];
    vi.spyOn(TMEClassifier as any, 'downloadFile').mockImplementation(async (url: unknown) => {
      urls.push(String(url));
      throw new Error('network disabled in this test');
    });
    // The files written below are zeros; read each as its pinned sha256.
    vi.spyOn(TMEClassifier as any, 'hashFileSync').mockImplementation(
      (path: unknown) => PINNED_SHA256[posix.basename(String(path))],
    );

    // Each run stops at the first file it cannot fetch. Creating that file
    // lets the next run reach the one after it, until every file is present.
    for (let i = 0; i < 10; i++) {
      const before = urls.length;
      await TMEClassifier.downloadModel(dir);
      if (urls.length === before) break;
      const name = posix.basename(new URL(urls[urls.length - 1]).pathname);
      writeFileSync(join(dir, name), Buffer.alloc(PINNED_BYTES[name] ?? 0));
    }

    expect(urls).toHaveLength(3);
    for (const url of urls) {
      expect(url.startsWith(`${MODEL_REPO}/resolve/`)).toBe(true);
      expect(url).toMatch(/\/resolve\/[0-9a-f]{40}\/[^/]+$/);
      expect(url).not.toContain('/resolve/main/');
    }
  });
});
