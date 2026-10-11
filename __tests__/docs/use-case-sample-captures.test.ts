/**
 * #981 — every `secure` sample in docs/use-cases that says it was captured
 * from this repository's test fixtures prints what the build prints.
 *
 * The blocks were pasted by hand and drifted as the scanner changed:
 * red-team-mcp read `7 critical issues found` and `15/100` where the build
 * printed 6 and 17; openclaw-security read `8 semantic finding(s)`, `15 high`
 * and `12 issues auto-fixable` against 11, 16 and 8; scan-my-agent read
 * `git hygiene (1 critical)` against `(1 critical, 1 low)`.
 *
 * scripts/use-case-samples.mjs renders each block from a fresh capture of its
 * fixture, with the doc's cuts applied by rule. This suite holds every block
 * to that rendering line for line, apart from the version on the
 * `Scanned with` line. A block that differs is regenerated with
 * `node scripts/use-case-samples.mjs --write`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import {
  SAMPLES,
  capturedBlocks,
  sampleBlockKey,
  findSampleBlock,
  seedClassifier,
  captureSample,
  renderSample,
  compareBlock,
} from '../../scripts/use-case-samples.mjs';

const ROOT = path.resolve(__dirname, '../..');

describe('#981 use-case samples match the build', () => {
  it('every block that presents itself as a fixture capture belongs to a sample', () => {
    const owned = SAMPLES.map(sampleBlockKey);
    expect(owned, 'a sample has no output block after its command').not.toContain(null);
    expect(capturedBlocks().sort()).toEqual([...owned].sort());
  });

  it('a version bump alone is not drift; any other changed line is', () => {
    const doc = ['  Security  ━━ 17/100', '  Scanned with hackmyagent v0.33.2'];
    expect(compareBlock(doc, ['  Security  ━━ 17/100', '  Scanned with hackmyagent v0.34.0'])).toBeNull();
    expect(compareBlock(doc, ['  Security  ━━ 15/100', '  Scanned with hackmyagent v0.33.2'])).toEqual({
      line: 1,
      documented: '  Security  ━━ 17/100',
      built: '  Security  ━━ 15/100',
    });
  });

  describe('against a fresh capture of each fixture', () => {
    // Each case runs the built CLI; a missing or stale build fails by name.
    beforeAll(assertDistFresh);

    // One HOME for every capture, so the classifier is fetched at most once.
    let home = '';
    beforeAll(() => {
      home = tempDir('hma-981-home-');
      seedClassifier(home);
    });

    for (const sample of SAMPLES) {
      it(`${sample.doc}: npx hackmyagent ${sample.args.join(' ')}`, (ctx) => {
        const capture = captureSample(sample, { home });
        if (!capture.classifier) ctx.skip('the NanoMind classifier could not be fetched; the samples are captures with it');
        const documented = findSampleBlock(readFileSync(path.join(ROOT, sample.doc), 'utf8'), sample)!.lines;
        const rendered = renderSample(sample, capture.lines);
        const diff = compareBlock(documented, rendered);
        expect(
          diff,
          diff ? `block line ${diff.line} differs from the build; regenerate with node scripts/use-case-samples.mjs --write` : '',
        ).toBeNull();
      });
    }
  });
});
