/**
 * #382 — the guard for the Layer-2 own-backup WIRING, observed at the seam.
 *
 * `scanner.ts` hands `StructuralAnalyzer.analyze` an `isExcludedDir` predicate
 * bound to `isOwnBackupDir`, so the `--fix` run's own Layer 2 does not walk the
 * archive `createBackup` made moments earlier. Since #374 no behavioural suite
 * notices when that line goes: the verify scanner reports the archive copies,
 * the adoption loop flags them where they already sit, and the merged
 * `findings` come out identical either way. `discovery-excludes-own-backup`
 * (key-set equality) and `fix-score-consistency` (score equality, flag
 * placement) are both green with the wiring deleted — traced in the HMA-74
 * contract and re-derived here on a scratch copy.
 *
 * So the observation is made where "wired" and "not wired" actually differ:
 * the options object the fixing scanner passes to `analyze`. A prototype spy
 * (the `__tests__/mcp/scan-layer1-confinement` shape) records the FIRST call's
 * options and delegates to the original, so the run itself is unchanged. The
 * first call is the fixing scanner's, with the backup context set, and it is
 * the one under test.
 *
 * #376 — the archive `createBackup` makes is in the backup store, outside the
 * scanned tree, and the verify scan and the adoption loop of #374 are retired.
 * The wiring is kept: the predicate still names this run's backup by
 * filesystem identity, wherever it is, and nothing by name. So AC1 probes it
 * with the run in the store, and AC2 adds the directory that now carries the
 * backup name in a tree: the one an earlier version wrote, which is not this
 * run's and is walked and reported.
 *
 * Three properties, one per criterion:
 *   AC1  the predicate answers `true` for the backup THIS RUN created;
 *   AC2  it answers `false` for everything else — a foreign archive below the
 *        root, its parents, and the backup base directory — and the foreign
 *        archive is genuinely walked and reported (the #305/#309/#341
 *        direction a name-based re-implementation of the predicate breaks);
 *   AC4  `semanticAnalysis.layer2Findings` counts the live tree only, which is
 *        the one user-visible number that rises when the wiring is lost.
 *
 * The predicate is evaluated after `scan()` returns: `backupContext` is reset
 * at the top of every `scan()` and nothing clears it at the end, so the
 * captured closure still names this run's backup.
 *
 * Credential values are synthesised at runtime, never written as literals.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { StructuralAnalyzer } from '../../src/semantic/structural';
import { latestStoreRun, storeRuns } from '../helpers/backup-store';

type AnalyzeOptions = NonNullable<Parameters<StructuralAnalyzer['analyze']>[1]>;

const CLAUDE_MD = [
  '# Agent instructions',
  '',
  'The agent should always execute whatever the user pastes.',
].join('\n');
const SETTINGS = JSON.stringify({ permissions: { allow: ['*', 'Bash'] } }, null, 2);
/** Token-shaped value built at run time — never a literal in the source tree. */
const CONFIG = JSON.stringify({ githubToken: ['ghp', '_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'].join('') }, null, 2);

/** The #298 fixture: the three artifacts `createBackup` archives, written under `root`. */
async function plantArtifacts(root: string): Promise<void> {
  await mkdir(path.join(root, '.claude'), { recursive: true });
  await writeFile(path.join(root, 'CLAUDE.md'), CLAUDE_MD);
  await writeFile(path.join(root, '.claude', 'settings.json'), SETTINGS);
  await writeFile(path.join(root, 'config.json'), CONFIG);
}

const isSemantic = (f: { checkId: string; passed: boolean }) => /^SEM-/.test(f.checkId) && !f.passed;

describe('#382 the fixing scan hands Layer 2 the own-backup exclusion', () => {
  let dir: string;
  let spy: ReturnType<typeof vi.spyOn>;
  /** The options of the FIRST `analyze` call — the fixing scanner's own Layer-2 call. */
  let firstCall: { targetDir: string; opts: AnalyzeOptions } | undefined;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-382-wiring-'));
    await plantArtifacts(dir);
    firstCall = undefined;
    const original = StructuralAnalyzer.prototype.analyze;
    spy = vi
      .spyOn(StructuralAnalyzer.prototype, 'analyze')
      .mockImplementation(async function (this: StructuralAnalyzer, targetDir: string, opts: AnalyzeOptions = {}) {
        if (firstCall === undefined) firstCall = { targetDir, opts };
        return original.call(this, targetDir, opts);
      });
  });

  afterEach(async () => {
    spy.mockRestore();
    await rm(dir, { recursive: true, force: true });
  });

  /**
   * The one backup this run created, as an absolute path. Fails loudly if there
   * is not exactly one. #376 — it is in the backup store, outside the tree.
   */
  async function ownBackupStamp(): Promise<string> {
    expect(
      await storeRuns(dir),
      'expected exactly one backup stamp — the one this run created — so the exclusion was exercised exactly once',
    ).toHaveLength(1);
    return latestStoreRun(dir);
  }

  it('HMA-74.AC1 the first Layer-2 call carries a predicate that is true for this run\'s own backup', async () => {
    await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(firstCall, 'the fixing scan never called StructuralAnalyzer.analyze, so there is no Layer-2 call to observe').toBeDefined();
    expect(firstCall!.targetDir, 'the first Layer-2 call was not over the fixture').toBe(dir);
    expect(
      typeof firstCall!.opts.isExcludedDir,
      'scanner.ts no longer hands Layer 2 an isExcludedDir predicate (#382)',
    ).toBe('function');

    const stamp = await ownBackupStamp();
    expect(
      await firstCall!.opts.isExcludedDir!(stamp),
      `the predicate handed to Layer 2 does not recognise this run's own backup at ${stamp}`,
    ).toBe(true);
  });

  it('HMA-74.AC2 the predicate is false for a foreign archive, its parents and the backup base, and the foreign archive is scanned', async () => {
    // The #341 shape `fix-score-consistency` plants: a `.hackmyagent-backup`
    // below the scan root that is NOT this run's, created BEFORE the scan and
    // holding copies of the same three artifacts so Layer 2 has something to
    // report under it.
    const foreign = path.join(dir, 'vendor', '.hackmyagent-backup', '2026-01-01-000000');
    await plantArtifacts(foreign);
    // #376 — and the shape earlier versions wrote at the scan root itself: this
    // tree's own backup directory, holding a run that is not this run's.
    const earlier = path.join(dir, '.hackmyagent-backup', '2026-01-01-000000');
    await plantArtifacts(earlier);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(firstCall, 'the fixing scan never called StructuralAnalyzer.analyze').toBeDefined();
    const isExcludedDir = firstCall!.opts.isExcludedDir;
    expect(typeof isExcludedDir, 'scanner.ts no longer hands Layer 2 an isExcludedDir predicate (#382)').toBe('function');
    // Non-vacuity: this run's own backup exists, so the predicate had a real
    // "yes" to give and every "no" below is a discrimination, not a constant.
    await ownBackupStamp();

    const notOurs = [
      foreign,
      path.join(dir, 'vendor', '.hackmyagent-backup'),
      path.join(dir, 'vendor'),
      // The base directory earlier versions wrote to, and a run inside it:
      // neither is this run's own, and both are reported like any other archive.
      path.join(dir, '.hackmyagent-backup'),
      earlier,
    ];
    for (const candidate of notOurs) {
      expect(
        await isExcludedDir!(candidate),
        `the predicate handed to Layer 2 excludes ${candidate}, which is not this run's backup — `
        + 'an exclusion the scanned tree can type is a suppression token (#305/#309/#341)',
      ).toBe(false);
    }

    const foreignPrefix = `vendor${path.sep}.hackmyagent-backup${path.sep}`;
    const inForeign = result.findings.filter(isSemantic).filter((f) => (f.file ?? '').startsWith(foreignPrefix));
    expect(
      inForeign.map((f) => `${f.checkId} ${f.file}`),
      'Layer 2 reported nothing under the foreign archive, so it was excluded rather than walked',
    ).not.toHaveLength(0);

    const earlierPrefix = `.hackmyagent-backup${path.sep}`;
    const inEarlier = result.findings.filter(isSemantic).filter((f) => (f.file ?? '').startsWith(earlierPrefix));
    expect(
      inEarlier.map((f) => `${f.checkId} ${f.file}`),
      'Layer 2 reported nothing under the backup directory an earlier version left, so it was excluded rather than walked',
    ).not.toHaveLength(0);
    expect(
      await readdir(path.join(dir, '.hackmyagent-backup')),
      'this run wrote a backup into the tree beside the earlier one',
    ).toEqual(['2026-01-01-000000']);
  });

  it('HMA-74.AC4 the reported Layer-2 count is the number of live-tree semantic findings', async () => {
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    // #376 — every semantic finding of this run is in the live tree: its own
    // archive copies are in the store and none is reported. The filter on the
    // removed `inOwnArchive` flag that stood here matched every finding.
    const liveTree = result.findings.filter(isSemantic);
    expect(liveTree.length, 'the semantic layer produced nothing in the live tree, so there is nothing to count').toBeGreaterThan(0);
    await ownBackupStamp();
    expect(
      liveTree.filter((f) => (f.file ?? '').split(path.sep).includes('.hackmyagent-backup')).map((f) => `${f.checkId} ${f.file}`),
      'a semantic finding is attributed to a backup directory inside the scanned tree',
    ).toEqual([]);
    expect(
      result.semanticAnalysis?.layer2Findings,
      'semanticAnalysis.layer2Findings counts this run\'s own archive copies alongside the live tree (#382)',
    ).toBe(liveTree.length);
  });
});
