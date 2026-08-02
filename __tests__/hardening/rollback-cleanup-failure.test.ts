/**
 * A backup that will not delete must not take the report down with it.
 *
 * `restoreFromBackup` ends by removing the backup it just used:
 *
 *     await fs.rm(backupReal, { recursive: true, force: true });
 *
 * `force: true` ignores exactly one thing — the path not existing. A `0500`
 * subdirectory inside the backup is enough to make it throw EACCES, because
 * `fs.rm` cannot unlink through a directory it may not write. It throws HERE,
 * after every file has been restored and the whole report assembled, so the
 * restored list, the unrestored list, `backup kept at` and "copy those files
 * back by hand" were all replaced by a bare errno.
 *
 * That is #344's harm through a different door — a completed report discarded
 * on the way out — and the barren-candidate change fires this `rm` on more runs
 * than before, so the door is wider than it was.
 *
 * The permissions here are ordinary. `0500` is what a careful person sets on a
 * directory they do not want written; it needs no attacker, and a forged backup
 * shipped in a cloned repo can carry it. Skipped only for root, which can
 * unlink through any mode and for whom the case does not exist.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import { mkdtemp, mkdir, writeFile, rm, chmod, readFile, access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

const STAMP = '2026-01-01-000000-000-abcdabcd';
const ORIGINAL = '{"token":"original-value"}\n';
const REWRITTEN = '{"token":"${GITHUB_TOKEN}"}\n';

/** Root ignores directory permissions, so the case cannot be built there. */
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

let dir: string;
let locked: string;

/**
 * A tree with a usable backup whose removal will fail: everything the manifest
 * lists restores cleanly, so the backup is due to be DELETED, and one
 * subdirectory inside it refuses.
 */
async function buildFixture(): Promise<void> {
  const backup = path.join(dir, '.hackmyagent-backup', STAMP);
  await mkdir(backup, { recursive: true });
  await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  // The live file as `--fix` left it, and the original inside the backup.
  await writeFile(path.join(dir, 'config.json'), REWRITTEN);
  await writeFile(path.join(backup, 'config.json'), ORIGINAL);
  await writeFile(
    path.join(backup, '.manifest.json'),
    JSON.stringify({ version: 2, existingFiles: ['config.json'], absentAtBackup: [], createdFiles: [] }),
  );
  // The obstacle: a directory inside the backup that cannot be emptied.
  locked = path.join(backup, 'locked');
  await mkdir(locked, { recursive: true });
  await writeFile(path.join(locked, 'stuck.txt'), 'x\n');
  await chmod(locked, 0o500);
}

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'hma-rm-guard-'));
});

afterEach(async () => {
  // Restore the mode first, or the temp tree cannot be removed either.
  if (locked) { try { await chmod(locked, 0o700); } catch { /* already gone */ } }
  if (dir) await rm(dir, { recursive: true, force: true });
  locked = '';
});

describe('#344 second door: a backup that cannot be deleted', () => {
  it.skipIf(isRoot)('restores the files and returns the report instead of throwing', async () => {
    await buildFixture();

    const report = await new HardeningScanner().rollback(dir);

    // The rollback itself worked, and that is the point: the failure is
    // housekeeping, and the account of the work must survive it.
    expect(
      report.restored,
      'the file was not restored, so this fixture is not exercising the case — '
      + 'the run failed before it reached the removal',
    ).toContain('config.json');
    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'the original bytes did not come back',
    ).toBe(ORIGINAL);

    // Non-vacuity: the removal really did fail. Without this the assertions
    // above pass on a machine where `0500` does not stop `fs.rm` — a root
    // container, or a filesystem that ignores modes.
    expect(
      report.backupRemovalFailed,
      'the backup was removed successfully, so nothing here tested the guard',
    ).toBeDefined();
    expect(report.backupRemovalFailed!.path).toContain(STAMP);
    expect(
      report.backupRemovalFailed!.reason,
      'the reason does not name the errno, so the user cannot tell a permission '
      + 'problem from a busy filesystem',
    ).toMatch(/EACCES|EPERM|ENOTEMPTY|EBUSY/);

    // And it is NOT reported as a deliberate retention: that channel means "kept
    // because it still holds the only copy", which is not what happened.
    expect(
      report.backupRetainedAt,
      'a failed cleanup was reported as a deliberate retention, so the report '
      + 'states a reason that is not the reason',
    ).toBeUndefined();
  }, 120_000);

  it.skipIf(isRoot)('says so on screen, with the path and what it means', async () => {
    // The scanner-level assertion above cannot see the renderer, and this
    // project has shipped a finding that existed in the code and appeared
    // nowhere on screen. `backupRetainedAt` renders only inside the
    // `unrestored` block, so reusing it here would have left the directory on
    // disk silently — which is why this has its own channel and its own case.
    assertDistFresh();
    await buildFixture();

    let out = '';
    try {
      out = execFileSync(process.execPath, [BUILT_CLI, 'rollback', dir], {
        encoding: 'utf8',
        timeout: 120_000,
        env: { ...process.env, NO_COLOR: '1', OPENA2A_CORPUS_DETERMINISTIC: '1' },
      });
    } catch (e: unknown) {
      const err = e as { stdout?: string; stderr?: string };
      out = `${String(err.stdout ?? '')}${String(err.stderr ?? '')}`;
    }

    // The backup is still there — the premise of everything below.
    await expect(
      access(path.join(dir, '.hackmyagent-backup', STAMP)),
      'the backup was removed, so this run did not exercise the failure',
    ).resolves.toBeUndefined();

    expect(
      out,
      'the report was replaced by a raw error, or the leftover backup was never '
      + 'mentioned: the user is left with a directory on disk that a later '
      + 'rollback can select again, and no line about it',
    ).toMatch(/backup could not be removed/i);
    expect(out, 'the leftover is not named, so the user cannot find it').toContain(STAMP);
    // The restore report survived the failure.
    expect(
      out,
      'the account of what was restored did not survive the cleanup failure',
    ).toContain('config.json');
    // A path forward, and deliberately not a pasteable `rm -rf` on a
    // tree-derived path — #326 removed the last of those.
    expect(out, 'the leftover is reported with no way forward').toMatch(/by hand/i);
    expect(out, 'a destructive recursive citation came back').not.toMatch(/rm -rf/);
  }, 120_000);

  /**
   * The report must not contradict itself, and must not claim a restore that
   * did not happen.
   *
   * The guard above stopped a failed cleanup throwing the report away, and then
   * the report it saved said three false things in five lines: the `unrestored`
   * suffix said the backup "was removed" directly above a block reporting that
   * it was not; the new block opened with "The rollback finished" under a
   * `Rollback incomplete` header; and it closed with "Your files were restored"
   * on a run that restored nothing. Fixing #344's truncation reintroduced #346's
   * self-contradiction, in the fix for it.
   */
  it.skipIf(isRoot)('does not contradict the block above it, or claim a restore that did not happen', async () => {
    // A manifest naming a file the backup does not hold: nothing restores, so
    // the backup is due for deletion, and the deletion fails.
    const backup = path.join(dir, '.hackmyagent-backup', STAMP);
    await mkdir(backup, { recursive: true });
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({ version: 2, existingFiles: ['missing.json'], absentAtBackup: [], createdFiles: [] }),
    );
    locked = path.join(backup, 'locked');
    await mkdir(locked, { recursive: true });
    await writeFile(path.join(locked, 'stuck.txt'), 'x\n');
    await chmod(locked, 0o500);

    assertDistFresh();
    let out = '';
    try {
      out = execFileSync(process.execPath, [BUILT_CLI, 'rollback', dir], {
        encoding: 'utf8',
        timeout: 120_000,
        env: { ...process.env, NO_COLOR: '1', OPENA2A_CORPUS_DETERMINISTIC: '1' },
      });
    } catch (e: unknown) {
      const err = e as { stdout?: string; stderr?: string };
      out = `${String(err.stdout ?? '')}${String(err.stderr ?? '')}`;
    }

    expect(
      out,
      'the cleanup did not fail, so this case measures nothing',
    ).toMatch(/could not be removed/i);
    expect(
      out,
      'the report says the backup was removed, and the block below says it was not',
    ).not.toMatch(/so it was removed/);
    expect(
      out,
      'a run that restored nothing told the user their files were restored',
    ).not.toMatch(/[Yy]our files were restored/);
    expect(
      out,
      'the cleanup block says the rollback finished, under a header saying it did not',
    ).not.toMatch(/rollback finished/i);
    // The header itself is still the truth about the restore.
    expect(out, 'an incomplete rollback no longer says so').toMatch(/Rollback incomplete/);
  }, 120_000);

  /**
   * CONTROL — the ordinary path still consumes the backup and says nothing.
   * Without it, every assertion above passes on a build that simply stopped
   * deleting backups.
   */
  it('removes the backup and reports no failure when nothing is in the way', async () => {
    const backup = path.join(dir, '.hackmyagent-backup', STAMP);
    await mkdir(backup, { recursive: true });
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
    await writeFile(path.join(dir, 'config.json'), REWRITTEN);
    await writeFile(path.join(backup, 'config.json'), ORIGINAL);
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({ version: 2, existingFiles: ['config.json'], absentAtBackup: [], createdFiles: [] }),
    );

    const report = await new HardeningScanner().rollback(dir);

    expect(report.restored).toContain('config.json');
    expect(
      report.backupRemovalFailed,
      'an ordinary rollback reported a cleanup failure that did not happen',
    ).toBeUndefined();
    await expect(
      access(backup),
      'the used backup was left on disk, which is the #338 wedge',
    ).rejects.toThrow();
  }, 120_000);
});
