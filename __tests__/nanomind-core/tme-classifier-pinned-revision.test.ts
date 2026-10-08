/**
 * #914 — the pinned size and sha256 of each classifier file describe the file
 * at the pinned model commit.
 *
 * `MODEL_FILES` is the only copy of those values, and every other test reads
 * it, so a mistyped sha256 or size passes them all and shows up only when a
 * user's download fails with "sha256 does not match the pinned value". This
 * test downloads the three files at the pinned commit through the classifier's
 * own download path, then hashes and sizes what arrived independently of it.
 *
 * It needs the network, so it runs only when HMA_VERIFY_MODEL_PINS=1 is set;
 * the release smoke test sets it (docs/testing/release-smoke.md, section 0).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { TMEClassifier, MODEL_FILES } from '../../src/nanomind-core/inference/tme-classifier';
import { tempDir } from '../helpers/temp-dir';

describe.skipIf(process.env.HMA_VERIFY_MODEL_PINS !== '1')('classifier pins match the files at the pinned commit (network)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('downloads every file and each one has its pinned size and sha256', { timeout: 170_000 }, async () => {
    const dir = tempDir('hma-model-revision-');
    const said: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      said.push(String(chunk));
      return true;
    });

    const ok = await TMEClassifier.downloadModel(dir, { idleTimeoutMs: 30_000 });
    expect(ok, said.join('')).toBe(true);

    const measured = MODEL_FILES.map(f => {
      const bytes = readFileSync(join(dir, f.name));
      return {
        name: f.name,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        bytes: statSync(join(dir, f.name)).size,
      };
    });
    expect(measured).toEqual(MODEL_FILES.map(f => ({ ...f })));
  });
});
