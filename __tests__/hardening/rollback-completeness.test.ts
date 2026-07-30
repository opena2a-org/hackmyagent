/**
 * #327 — a rollback either puts every listed file back, or says which ones it
 * could not and keeps the copies.
 *
 * The #318 fix refused any destination whose LEAF was a symlink. But `--fix`
 * writes THROUGH a symlinked config — `ensureBackupCovers` says so explicitly —
 * so an ordinary dotfile-sharing layout was backed up, redacted, and then could
 * not be restored. Nothing reported it (`RollbackReport` had no channel for
 * "listed, not restored"), and the backup holding the only copy was deleted
 * anyway. Measured, with no attacker and no forged manifest:
 *
 *   config.json -> shared/actual.json
 *   secure --fix        live file redacted, backup holds the ORIGINAL
 *   rollback            "[+] Rollback complete", exit 0, 1 file restored
 *   after               original recovered: false
 *                       ANY copy of the original left in the tree: false
 *
 * That is the #317 harm statement verbatim, reintroduced by the fix for #318.
 *
 * Two independent properties, tested independently here: the refusal must be
 * about where the link GOES (not that it is a link), and a refusal must be
 * reported and must not consume the backup.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { access, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

const exists = async (p: string): Promise<boolean> => {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
};

describe('#327 a rollback reports what it could not restore', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-327-'));
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /**
   * The regression itself. `config.json -> shared/actual.json` is an ordinary
   * layout; HMA followed the link on the way in, so it must follow it on the way
   * back.
   */
  it('restores a config reached through an in-tree symlink, and keeps the link', async () => {
    const real = path.join(dir, 'shared', 'actual.json');
    await mkdir(path.dirname(real), { recursive: true });
    const original = `${JSON.stringify({ token: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`;
    await writeFile(real, original);
    await symlink(path.join('shared', 'actual.json'), path.join(dir, 'config.json'));

    const scanner = new HardeningScanner();
    await scanner.scan({ targetDir: dir, autoFix: true });

    // Non-vacuity: the fix must actually have rewritten the far end, or there is
    // nothing for the rollback to undo.
    expect(
      await readFile(real, 'utf-8'),
      'the fix did not redact through the symlink; this test measures nothing',
    ).toContain('${GITHUB_TOKEN}');

    const report = await scanner.rollback(dir);

    expect(report.restored, 'the symlinked config was not restored').toContain('config.json');
    expect(report.unrestored, 'a legitimate restore was reported as a failure').toEqual([]);
    expect(await readFile(real, 'utf-8'), 'the original bytes were not recovered').toBe(original);
    expect(
      (await lstat(path.join(dir, 'config.json'))).isSymbolicLink(),
      'the restore replaced the symlink with a regular file',
    ).toBe(true);
  }, 120_000);

  /**
   * The other half: a destination that genuinely must be refused is REPORTED,
   * and the backup that still holds the only copy is kept. The refusal itself is
   * #318's property and is asserted here too — the victim file outside the tree
   * must not be written.
   */
  it('reports an unrestorable entry, keeps the backup, and leaves the out-of-tree file alone', async () => {
    const outside = await mkdtemp(path.join(tmpdir(), 'hma-327-victim-'));
    try {
      const victim = path.join(outside, 'authorized_keys');
      await writeFile(victim, 'VICTIM CONTENT\n');

      // `9999-99-99-999999` sorts above any real stamp, so this is the backup
      // `rollback` selects (#312).
      const backup = path.join(dir, '.hackmyagent-backup', '9999-99-99-999999');
      await mkdir(path.join(backup, 'evil', 'sshlink'), { recursive: true });
      await mkdir(path.join(dir, 'evil'), { recursive: true });
      await symlink(outside, path.join(dir, 'evil', 'sshlink'));
      await writeFile(path.join(backup, 'evil', 'sshlink', 'authorized_keys'), 'ATTACKER KEY\n');

      // A legitimate entry beside it, so the run restores something and the
      // report has to distinguish the two.
      await writeFile(path.join(dir, 'package.json'), '{"name":"live","version":"2.0.0"}\n');
      await writeFile(path.join(backup, 'package.json'), '{"name":"original","version":"1.0.0"}\n');
      await writeFile(
        path.join(backup, '.manifest.json'),
        JSON.stringify({
          version: 2,
          existingFiles: ['package.json', path.join('evil', 'sshlink', 'authorized_keys')],
          absentAtBackup: [],
          createdFiles: [],
        }),
      );

      const report = await new HardeningScanner().rollback(dir);

      expect(report.restored, 'the legitimate entry was not restored').toContain('package.json');
      // `?? []` so a build with NO channel at all fails on the assertion below —
      // which is the defect — rather than on a TypeError that says nothing.
      expect(
        (report.unrestored ?? []).map((u) => u.path),
        'the entry that could not be restored was not reported',
      ).toContain(path.join('evil', 'sshlink', 'authorized_keys'));
      expect(report.unrestored?.[0]?.reason, 'the report does not say why').toBeTruthy();
      expect(
        report.backupRetainedAt,
        'the backup holding the only copy was deleted anyway',
      ).toBeTruthy();
      expect(await exists(backup), 'the backup directory is gone').toBe(true);
      expect(
        await readFile(victim, 'utf-8'),
        'the out-of-tree file was written through the symlink',
      ).toBe('VICTIM CONTENT\n');
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  /**
   * #334 — a FILE in the backup base is not a backup.
   *
   * The selection filtered dotfiles and nothing else, so an ordinary file named
   * `zzz` — which sorts above every stamp — was chosen as "the most recent
   * backup", and every legitimate rollback in that tree failed on it under a
   * message naming a `.manifest.json` that was never opened.
   */
  it('ignores a non-directory in the backup base and rolls back the real one', async () => {
    await writeFile(
      path.join(dir, 'config.json'),
      `${JSON.stringify({ token: FAKE_GH_TOKEN }, null, 2)}\n`,
    );

    const scanner = new HardeningScanner();
    await scanner.scan({ targetDir: dir, autoFix: true });
    // Dropped in after the backup exists, so it can only affect SELECTION.
    await writeFile(path.join(dir, '.hackmyagent-backup', 'zzz'), 'not a backup\n');

    const report = await scanner.rollback(dir);

    expect(
      report.restored,
      'a file in the backup base was selected as the latest backup, so the real one was never used',
    ).toContain('config.json');
  }, 120_000);

  /**
   * The control that keeps the assertion above from being satisfied by "never
   * delete the backup". A rollback that restored everything still consumes it.
   *
   * Deliberately written to PASS against the pre-fix build as well (`?? []`):
   * this case describes behaviour that was already correct, and a control that
   * goes red on the base commit is not a control.
   */
  it('still deletes the backup when everything was restored (the control)', async () => {
    await writeFile(
      path.join(dir, 'config.json'),
      `${JSON.stringify({ token: FAKE_GH_TOKEN }, null, 2)}\n`,
    );

    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: dir, autoFix: true });
    expect(
      result.findings.some((f) => f.checkId === 'CRED-001'),
      'no credential was detected, so no backup was taken',
    ).toBe(true);

    const report = await scanner.rollback(dir);

    expect(report.unrestored ?? [], 'a clean round trip reported a failure').toEqual([]);
    expect(report.backupRetainedAt, 'a completed rollback kept its backup').toBeUndefined();
    expect(
      await exists(path.join(dir, '.hackmyagent-backup', '9999-99-99-999999')),
      'unexpected backup directory',
    ).toBe(false);
  }, 120_000);
});

/**
 * The user-visible half. A library caller can read `unrestored`; a person reads
 * the terminal, and a script reads the exit code. Both said the revert was
 * clean.
 */
describe('#327 the CLI does not report a rollback it did not complete', () => {
  let dir: string;

  beforeEach(async () => {
    assertDistFresh();
    dir = await mkdtemp(path.join(tmpdir(), 'hma-327-cli-'));
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('says incomplete, names the file and the retained backup, and exits 1', async () => {
    const outside = await mkdtemp(path.join(tmpdir(), 'hma-327-cli-victim-'));
    try {
      await writeFile(path.join(outside, 'authorized_keys'), 'VICTIM CONTENT\n');
      const backup = path.join(dir, '.hackmyagent-backup', '9999-99-99-999999');
      await mkdir(path.join(backup, 'evil', 'sshlink'), { recursive: true });
      await mkdir(path.join(dir, 'evil'), { recursive: true });
      await symlink(outside, path.join(dir, 'evil', 'sshlink'));
      await writeFile(path.join(backup, 'evil', 'sshlink', 'authorized_keys'), 'ATTACKER KEY\n');
      await writeFile(
        path.join(backup, '.manifest.json'),
        JSON.stringify({
          version: 2,
          existingFiles: [path.join('evil', 'sshlink', 'authorized_keys')],
          absentAtBackup: [],
          createdFiles: [],
        }),
      );

      let out = '';
      let status = 0;
      try {
        out = execFileSync(process.execPath, [BUILT_CLI, 'rollback', dir], {
          encoding: 'utf8',
          timeout: 120_000,
          env: { ...process.env, NO_COLOR: '1' },
        });
      } catch (e: unknown) {
        const err = e as { stdout?: string; status?: number };
        out = String(err.stdout ?? '');
        status = err.status ?? 0;
      }

      expect(status, 'an incomplete rollback exited 0, so a script would read it as done')
        .toBe(1);
      expect(out, 'the report claimed a clean revert').not.toContain('Rollback complete');
      expect(out).toContain('Rollback incomplete');
      expect(out, 'the file that was not restored is not named').toContain('authorized_keys');
      expect(out, 'the user is not told the backup was kept, or where').toContain('backup kept at');
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  }, 120_000);
});
