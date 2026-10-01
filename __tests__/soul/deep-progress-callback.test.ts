/**
 * #285 / #260 — the `--deep` progress counter is driven by `scanSoul` itself.
 *
 * `scan-soul --deep` makes one semantic round-trip per undetected control, and
 * without a counter the command read as a hang (#260). The CLI half is covered:
 * `shouldShowDeepProgress` decides whether to render. The scanner half was not:
 * deleting the `options?.onProgress?.(analyzed, total)` call in
 * `src/soul/scanner.ts` left every test green, because nothing called
 * `scanSoul` with `deepAnalysis` and a callback. No spawn test can reach it
 * either: the deep tier needs an analysis backend, and the counter is TTY-only.
 *
 * The backend is stubbed at the two private seams the deep pass calls, so the
 * run is offline and deterministic. The assertion is the counter's contract:
 * one call per analysed control, counting from 0, with a constant total equal
 * to the number of controls actually sent for analysis.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { SoulScanner } from '../../src/soul/scanner';

type DeepSeams = { isLlmAvailable(): boolean; analyzeControlDeep(): Promise<boolean> };
const seams = SoulScanner.prototype as unknown as DeepSeams;

function soulDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-285-deep-'));
  // Sparse on purpose: most applicable controls go undetected by the keyword
  // tier, so the deep pass has several controls to count through.
  writeFileSync(path.join(dir, 'SOUL.md'), '# Assistant\n\nA helpful assistant for internal documentation.\n');
  return dir;
}

afterEach(() => { vi.restoreAllMocks(); });

describe('#285 scanSoul reports deep-pass progress per analysed control', () => {
  it('calls onProgress once per control sent for analysis, counting up to the total', async () => {
    vi.spyOn(seams, 'isLlmAvailable').mockReturnValue(true);
    const deep = vi.spyOn(seams, 'analyzeControlDeep').mockResolvedValue(false);
    const calls: Array<[number, number]> = [];

    await new SoulScanner().scanSoul(soulDir(), {
      deepAnalysis: true,
      onProgress: (analyzed, total) => calls.push([analyzed, total]),
    });

    const analysed = deep.mock.calls.length;
    expect(analysed, 'the fixture must leave controls for the deep pass').toBeGreaterThan(1);
    expect(calls).toEqual(Array.from({ length: analysed }, (_, i) => [i, analysed]));
  });

  it('does not call onProgress when the deep pass does not run', async () => {
    const deep = vi.spyOn(seams, 'analyzeControlDeep').mockResolvedValue(false);
    const onProgress = vi.fn();

    await new SoulScanner().scanSoul(soulDir(), { onProgress });
    expect(deep).not.toHaveBeenCalled();
    expect(onProgress).not.toHaveBeenCalled();

    // Requested, but no backend: the pass is skipped, so nothing is counted.
    vi.spyOn(seams, 'isLlmAvailable').mockReturnValue(false);
    await new SoulScanner().scanSoul(soulDir(), { deepAnalysis: true, onProgress });
    expect(deep).not.toHaveBeenCalled();
    expect(onProgress).not.toHaveBeenCalled();
  });
});
