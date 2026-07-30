/**
 * #333 — a failed identity probe is not a "no".
 *
 * `identityOf` swallowed every errno and returned null, and null means "not our
 * backup" to both callers. For the detection walk that is fail-closed: the
 * directory gets scanned, so nothing is hidden. For the WRITE gate it is
 * fail-open — `isInsideOwnBackup` returning false there means ALLOW THE WRITE —
 * so an `EACCES`, `ELOOP`, `EIO` or `EMFILE` on any ancestor `stat` during a
 * `--fix` run left HackMyAgent free to rewrite its own backup, with only the
 * name check standing in the way.
 *
 * The errno here is produced by a real filesystem object, not by a mock: a
 * symlink loop makes `stat` fail with ELOOP on every platform and for every
 * user, where a chmod fixture would answer differently as root.
 *
 * Why the write-gate consequence is asserted at the predicate rather than
 * end-to-end: an ancestor that cannot be stat-ed also cannot be traversed, so
 * any fixture that blocks the probe blocks the write for unrelated reasons and
 * would pass for the wrong reason. The errno that IS reachable with the write
 * still succeeding is transient — fd exhaustion (EMFILE/ENFILE) — which cannot
 * be staged deterministically. So the direction is pinned where the decision is
 * made.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

type Probe = HardeningScanner & {
  backupContext?: {
    backupDir: string;
    backupIdent: { dev: number; ino: number };
    targetDir: string;
    covered: Set<string>;
  };
  isInsideOwnBackup(absPath: string): Promise<'yes' | 'no' | 'unknown'>;
};

describe('#333 the identity probe reports what it could not establish', () => {
  let dir: string;
  let scanner: Probe;
  let backupDir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-333-'));
    backupDir = path.join(dir, '.hackmyagent-backup', '2026-01-02-030405678-000-abcdabcd');
    await mkdir(backupDir, { recursive: true });
    const { stat } = await import('node:fs/promises');
    const st = await stat(backupDir);
    scanner = new HardeningScanner() as unknown as Probe;
    scanner.backupContext = {
      backupDir,
      backupIdent: { dev: st.dev, ino: st.ino },
      targetDir: dir,
      covered: new Set(),
    };
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('says "unknown" when an ancestor cannot be examined', async () => {
    // A symlink loop: `stat` through it fails ELOOP, which proves nothing about
    // whether the path is inside HackMyAgent's own backup.
    await symlink(path.join(dir, 'loop-b'), path.join(dir, 'loop-a'));
    await symlink(path.join(dir, 'loop-a'), path.join(dir, 'loop-b'));

    const verdict = await scanner.isInsideOwnBackup(path.join(dir, 'loop-a', 'inner', 'config.json'));

    expect(
      verdict,
      'an ancestor the filesystem would not describe was reported as "not our backup", '
      + 'which at the write gate means: go ahead and write',
    ).toBe('unknown');
  });

  /**
   * Both controls, so "unknown" cannot be the answer to everything: an ordinary
   * path outside the backup is still "no", and a path inside it is still "yes".
   *
   * The two answers that already existed are read through `asVerdict`, so this
   * case describes behaviour that was correct before the change and passes
   * against the previous build too. A control that goes red on the base commit
   * is not a control.
   */
  /**
   * The write gate is the caller this matters for, so the branch it takes is
   * asserted here rather than left to the predicate alone. `applyFixWrite`
   * consults the identity FIRST, so the recorded failure code says which guard
   * refused: an unreadable ancestor must be reported as exactly that, not as the
   * "no recoverable backup copy" the later guard would report.
   */
  it('refuses the write with its own cause when the identity cannot be established', async () => {
    await symlink(path.join(dir, 'loop-b'), path.join(dir, 'loop-a'));
    await symlink(path.join(dir, 'loop-a'), path.join(dir, 'loop-b'));

    const probe = scanner as unknown as {
      applyFixWrite(p: string, c: string): Promise<boolean>;
      fixWriteFailures: Array<{ file: string; code: string; message: string }>;
    };

    const wrote = await probe.applyFixWrite(path.join(dir, 'loop-a', 'inner', 'config.json'), 'X\n');

    expect(wrote, 'the write was authorised although the identity could not be established').toBe(false);
    expect(
      probe.fixWriteFailures.map((f) => f.code),
      'the refusal was attributed to a cause that was never established',
    ).toContain('BACKUP-IDENTITY-UNKNOWN');
  });

  it('still answers no for an ordinary path and yes for one inside the backup', async () => {
    const asVerdict = (v: unknown): unknown => (v === true ? 'yes' : v === false ? 'no' : v);

    expect(
      asVerdict(await scanner.isInsideOwnBackup(path.join(dir, 'config.json'))),
      'an ordinary in-tree path is no longer writable',
    ).toBe('no');
    expect(
      asVerdict(await scanner.isInsideOwnBackup(path.join(backupDir, 'config.json'))),
      'the run stopped recognising its own backup',
    ).toBe('yes');
  });
});
