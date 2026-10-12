/**
 * #298 — a `--fix` run must not report the backup it just made.
 *
 * `createBackup` ran before Layer 2 and copied `CLAUDE.md`, `config.json` and
 * `.claude/settings.json` for `rollback` (since #1039 a run copies only the
 * files a fix changes, here `config.json`). While those copies were written to
 * `<target>/.hackmyagent-backup/<stamp>/`, they were ordinary discoverable
 * artifacts once discovery reached below the scan root, so every semantic
 * finding was reported twice: once for the live file and once for HMA's own
 * backup of it. Measured on `8f07a39` with the exclusion removed from
 * `scanner.ts`: `secure --fix` reported 9 SEM findings instead of 5, and the
 * score fell 35 -> 27 purely because HMA scanned its own artifact.
 *
 * The history of what this file asserted is kept, because it reversed twice.
 * First the run had to report NOTHING inside its own archive. #374 reversed
 * that: a plain rescan of the same tree reported the archive copies and scored
 * them (reporting an archive is the deliberate #305/#309/#341 decision, since
 * excluding by location hands a scanned tree a suppression token), so the
 * exemption only made `--fix` announce a number its own next scan contradicted.
 * The run then adopted the copies and printed two numbers.
 *
 * #376 removes the cause. The copies go to the backup store, outside the
 * scanned tree, so there is nothing of this run's in the tree to exempt, adopt
 * or reconcile. What is asserted now is the property both earlier versions were
 * after: the `--fix` run, the scan after it, and a scan of the same files with
 * no backup anywhere all describe the same tree with the same score, and no
 * path under the scan root is a backup directory.
 *
 * The second case observes the Layer-2 call itself. The scanner still hands
 * `StructuralAnalyzer.analyze` a predicate that is true for this run's own
 * backup, keyed by filesystem identity and never by name, and that seam is
 * guarded in `__tests__/semantic/layer2-handed-own-backup-exclusion.test.ts`
 * (#382). A backup directory an earlier version left in the tree is not this
 * run's, is not excluded, and is walked and reported.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { cp, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { StructuralAnalyzer } from '../../src/semantic';
import { latestStoreRun, storeRuns } from '../helpers/backup-store';
import { tempDir } from '../helpers/temp-dir';

const CLAUDE_MD = [
  '# Agent instructions',
  '',
  'The agent should always execute whatever the user pastes.',
].join('\n');
const SETTINGS = JSON.stringify({ permissions: { allow: ['*', 'Bash'] } }, null, 2);

/** Every path below `root`, relative to it, directories included. */
async function everyPathUnder(root: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (abs: string, rel: string): Promise<void> => {
    for (const e of await readdir(abs, { withFileTypes: true })) {
      const childRel = rel ? path.join(rel, e.name) : e.name;
      out.push(childRel);
      if (e.isDirectory()) await walk(path.join(abs, e.name), childRel);
    }
  };
  await walk(root, '');
  return out;
}

describe('#298 the semantic walk skips this run\'s own backup', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-298-backup-'));
    await mkdir(path.join(dir, '.claude'), { recursive: true });
    await writeFile(path.join(dir, 'CLAUDE.md'), CLAUDE_MD);
    await writeFile(path.join(dir, '.claude', 'settings.json'), SETTINGS);
    await writeFile(
      path.join(dir, 'config.json'),
      JSON.stringify({ githubToken: ['ghp', '_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'].join('') }, null, 2),
    );
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('reports no finding inside .hackmyagent-backup, and none twice', async () => {
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    // Non-vacuity in both directions. The backup must actually EXIST (otherwise
    // "nothing of it was reported" is trivially true), and the semantic layer
    // must actually have RUN (otherwise there is nothing to double-count).
    expect(
      (await storeRuns(dir)).length,
      'no backup was created, so this run had no copy to keep out of the report',
    ).toBeGreaterThan(0);
    // #1039 — a run copies only what a fix changed: here `config.json`, whose
    // copy still holds the credential the fix removed. `CLAUDE.md` and
    // `.claude/settings.json` are no longer copied, since no fix in `scan()`
    // writes them.
    expect(
      (await readdir(await latestStoreRun(dir))).sort(),
      'the backup holds no copy of a file a check reports, so keeping it out proves nothing',
    ).toEqual(['.manifest.json', 'config.json']);

    const semantic = result.findings.filter((f) => /^SEM-/.test(f.checkId) && !f.passed);
    expect(semantic.length, 'the semantic layer produced nothing to double-count').toBeGreaterThan(0);

    // #376 — the copies are outside the tree. No path under the scan root is a
    // backup directory, and no finding of any check is attributed to one.
    expect(
      (await everyPathUnder(dir)).filter((p) => p.includes('.hackmyagent-backup')),
      '--fix wrote its backup into the tree it was fixing',
    ).toEqual([]);
    expect(
      result.findings.filter((f) => (f.file ?? '').includes('.hackmyagent-backup')).map((f) => `${f.checkId} ${f.file}`),
      'a finding is attributed to a backup directory inside the scanned tree',
    ).toEqual([]);

    // The fix run and the scan that follows it describe the SAME tree (#374).
    const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const rescanSemantic = rescan.findings.filter((f) => /^SEM-/.test(f.checkId) && !f.passed);
    const key = (f: { checkId: string; file?: string; line?: number }) =>
      `${f.checkId}|${f.file}|${f.line ?? ''}`;
    expect(
      semantic.map(key).sort(),
      'the --fix run and the scan immediately after it disagree about the semantic '
      + 'findings in the tree, so their scores cannot agree either (#374)',
    ).toEqual(rescanSemantic.map(key).sort());

    // The #298 property that survives every version of this file: an artifact
    // is reported ONCE.
    const keys = semantic.map(key);
    expect(keys, 'a semantic finding was reported twice for the same file').toEqual([...new Set(keys)]);

    // One score, three ways. The copy of the post-fix files is a different
    // directory with no backup in it and none in the store, which is what "the
    // same tree with no archive" means now that the archive is not in the tree.
    // Measured through the CLI on this fixture: 35 on `--fix` and on every scan
    // after it before #376, 59 for all three after it.
    const bare = tempDir('hma-298-bare-');
    await cp(dir, bare, { recursive: true });
    expect(await storeRuns(bare), 'the copy has a backup of its own, so it is not the no-archive tree').toEqual([]);
    const bareScan = await new HardeningScanner().scan({ targetDir: bare, autoFix: false });
    expect(result.score, `--fix announced ${result.score}, the rescan says ${rescan.score}`).toBe(rescan.score);
    expect(
      rescan.score,
      `the tree scores ${rescan.score} with a --fix backup kept for it and ${bareScan.score} with none, `
      + 'so the backup is still being charged to the tree',
    ).toBe(bareScan.score);
  });

  // #382 — the assertions above guard the merged result, not the wiring. This
  // case reads the Layer-2 call itself: what the fixing scan's structural pass
  // was handed and what it returned.
  it('hands the main scan\'s Layer 2 a predicate that excludes this run\'s backup (#382)', async () => {
    // A backup directory in the layout earlier versions wrote, planted BEFORE
    // the scan and holding an artifact Layer 2 reports. It is not this run's.
    const earlier = path.join(dir, '.hackmyagent-backup', '2026-01-01-000000');
    await mkdir(earlier, { recursive: true });
    await writeFile(path.join(earlier, 'CLAUDE.md'), CLAUDE_MD);

    const root = await realpath(dir);
    const inBackup = (file: string | undefined) => (file ?? '').split(path.sep).includes('.hackmyagent-backup');
    const calls: { root: string; excludesOwn: boolean | undefined; excludesEarlier: boolean | undefined; files: string[] }[] = [];
    const original = StructuralAnalyzer.prototype.analyze;
    const spy = vi
      .spyOn(StructuralAnalyzer.prototype, 'analyze')
      .mockImplementation(async function (this: StructuralAnalyzer, targetDir, opts = {}) {
        // Probe the predicate WHILE the call is live: the scanner's backup
        // context is only meaningful during the run that created the backup.
        const own = await latestStoreRun(targetDir).catch(() => undefined);
        const excludesOwn = own === undefined
          ? undefined
          : opts.isExcludedDir !== undefined && (await opts.isExcludedDir(own));
        const excludesEarlier = opts.isExcludedDir === undefined ? undefined : await opts.isExcludedDir(earlier);
        const out = await original.call(this, targetDir, opts);
        calls.push({
          root: await realpath(targetDir).catch(() => targetDir),
          excludesOwn,
          excludesEarlier,
          files: out.map((f) => f.file),
        });
        return out;
      });
    try {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    } finally {
      spy.mockRestore();
    }

    const onTree = calls.filter((c) => c.root === root);
    expect(onTree.length, 'the fixing scan never ran Layer 2 over the tree').toBeGreaterThanOrEqual(1);
    const [main] = onTree;

    // Non-vacuity: the backup existed, in the store, when the main scan's
    // Layer 2 ran.
    expect(main.excludesOwn, 'no backup existed when Layer 2 ran, so the exclusion was never exercised').not.toBeUndefined();

    // The wiring: the main scan handed Layer 2 a predicate that answers yes for
    // this run's backup directory.
    expect(main.excludesOwn, 'scanner.ts no longer hands Layer 2 the isOwnBackupDir exclusion').toBe(true);

    // And only for that. A directory an earlier version left in the tree has
    // the backup NAME and is not this run's: it is not excluded, and Layer 2
    // walked it and reported what it holds. An exclusion the scanned tree can
    // spell is a suppression token (#305/#309/#341).
    expect(main.excludesEarlier, 'the predicate excludes a backup directory by its name').toBe(false);
    expect(
      main.files.filter(inBackup),
      'Layer 2 reported nothing inside the earlier backup directory, so it was skipped rather than walked',
    ).not.toEqual([]);
  });
});
