/**
 * One `HardeningScanner` instance, two overlapping `scan()` calls.
 *
 * The per-scan ledger keeps each scan's withholding DECISIONS on its own roots
 * (concurrent-scan-isolation.test.ts drives one instance per scan). The
 * per-run state the result is built from used to live on the instance: every
 * `scan()` overwrote `this.coverage`, the CLI name and the fix bookkeeping,
 * so when two calls on the same instance overlapped, each result reported the
 * ledger, and the CLI name, of whichever scan had started last. Measured on
 * the all-basenames link fixture: result A listed the withheld links of trees
 * A and B together.
 *
 * Each overlapping scan must report exactly what the same scan reports when it
 * runs alone on the same instance: its own withheld links, resolved into its
 * own out-of-tree directory, with a retarget command naming its own CLI.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { buildLinkFixture, type LinkFixture } from '../helpers/out-of-tree-link-fixture';

let fxA: LinkFixture;
let fxB: LinkFixture;

beforeAll(() => {
  fxA = buildLinkFixture('hma-one-instance-a-');
  fxB = buildLinkFixture('hma-one-instance-b-');
});

afterAll(() => {
  fs.rmSync(fxA.base, { recursive: true, force: true });
  fs.rmSync(fxB.base, { recursive: true, force: true });
});

type Scanned = Awaited<ReturnType<HardeningScanner['scan']>>;

const scanWith = (scanner: HardeningScanner, dir: string, cliName: string): Promise<Scanned> =>
  scanner.scan({
    targetDir: dir, autoFix: false, dryRun: false, ignore: [], deep: false,
    scanDepth: 'standard', cliName,
  });

const links = (result: Scanned) => [...(result.withheldLinks ?? [])]
  .sort((a, b) => a.rel.localeCompare(b.rel));

describe('one scanner instance driven by two overlapping scans', () => {
  it('each result lists only its own withheld links, with its own CLI name in the retarget command', async () => {
    const scanner = new HardeningScanner();

    // The control: the same instance, one scan at a time.
    const seqA = await scanWith(scanner, fxA.linked, 'hackmyagent');
    const seqB = await scanWith(scanner, fxB.linked, 'opena2a');

    // Non-vacuity: each tree's planted links are withheld when it runs alone,
    // and the two CLI names really differ in the records.
    for (const [seq, fx] of [[seqA, fxA], [seqB, fxB]] as const) {
      const rels = links(seq).map((w) => w.rel);
      for (const planted of fx.plantedLinks) expect(rels).toContain(planted.rel);
    }
    expect(links(seqA).every((w) => w.retarget.includes('hackmyagent secure'))).toBe(true);
    expect(links(seqB).every((w) => w.retarget.includes('opena2a secure'))).toBe(true);

    const [conA, conB] = await Promise.all([
      scanWith(scanner, fxA.linked, 'hackmyagent'),
      scanWith(scanner, fxB.linked, 'opena2a'),
    ]);

    for (const w of links(conA)) {
      expect(w.resolved.startsWith(fxA.shared + path.sep), `${w.rel} -> ${w.resolved} belongs to tree A`).toBe(true);
    }
    for (const w of links(conB)) {
      expect(w.resolved.startsWith(fxB.shared + path.sep), `${w.rel} -> ${w.resolved} belongs to tree B`).toBe(true);
    }
    expect(links(conA)).toEqual(links(seqA));
    expect(links(conB)).toEqual(links(seqB));
  }, 300_000);
});
