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

    // Each run stops at the first file it cannot fetch. Creating that file
    // lets the next run reach the one after it, until every file is present.
    for (let i = 0; i < 10; i++) {
      const before = urls.length;
      await TMEClassifier.downloadModel(dir, true);
      if (urls.length === before) break;
      writeFileSync(join(dir, posix.basename(new URL(urls[urls.length - 1]).pathname)), '');
    }

    expect(urls).toHaveLength(3);
    for (const url of urls) {
      expect(url.startsWith(`${MODEL_REPO}/resolve/`)).toBe(true);
      expect(url).toMatch(/\/resolve\/[0-9a-f]{40}\/[^/]+$/);
      expect(url).not.toContain('/resolve/main/');
    }
  });
});
