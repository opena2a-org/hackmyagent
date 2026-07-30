/**
 * #342/#347 — the report says what happened, and the guards that decide it are
 * observed by something.
 *
 * #327's stated property is that a rollback either puts every listed file back
 * or says which ones it could not. Only `existingFiles` got that channel: a
 * `createdFiles` entry whose destination would not resolve was dropped with a
 * bare `continue`, and so was a legacy entry. Measured on both the base and the
 * tip, so this was a gap rather than a regression:
 *
 *   ln -s real-file.json SOUL.md
 *   manifest: createdFiles [{path: "SOUL.md", sha256: <hash of real-file.json>}]
 *
 *   [+] Rollback complete
 *      Restored 0 modified files, removed 0 generated files.
 *   exit 0   SOUL.md still present: yes   backup deleted: yes
 *
 * The file HackMyAgent said it would remove is still there, it appears in none
 * of `removed` / `keptModified` / `keptUnverifiable` / `unrestored`, the run
 * claims completion, and the backup is consumed. The test added with #327 builds
 * this exact fixture and asserts only that the LINK'S TARGET survived — never
 * that the user is told — which is why the gap survived the change named for it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner, backupIdentityOrThrow } from '../../src/hardening/scanner';

const FORGED = '9999-99-99-999999';

const exists = async (p: string): Promise<boolean> => {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
};

describe('#342 a rollback reports the generated files it could not act on', () => {
  let dir: string;
  let backup: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-342-'));
    backup = path.join(dir, '.hackmyagent-backup', FORGED);
    await mkdir(backup, { recursive: true });
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('names a createdFiles entry it could not remove, and does not claim completion', async () => {
    const contents = '{"the-user-wrote-this":true}\n';
    await writeFile(path.join(dir, 'real-file.json'), contents);
    await symlink('real-file.json', path.join(dir, 'SOUL.md'));
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: [],
        absentAtBackup: [],
        createdFiles: [{
          path: 'SOUL.md',
          sha256: createHash('sha256').update(contents).digest('hex'),
        }],
      }),
    );

    const report = await new HardeningScanner().rollback(dir);

    expect(
      report.unremoved.map((u) => u.path),
      'the file HackMyAgent said it would remove is still there and appears in no channel',
    ).toContain('SOUL.md');
    expect(report.unremoved[0]?.reason, 'the report does not say why').toBe(
      'a symbolic link stands where the file should be',
    );
    // The refusal itself is #327's, and it must survive: unlinking through the
    // link would delete what it points at.
    expect(report.removed, 'rollback unlinked through a symlinked leaf').not.toContain('SOUL.md');
    expect(await exists(path.join(dir, 'SOUL.md'))).toBe(true);
  });

  it('names a legacy entry it could not resolve', async () => {
    await writeFile(path.join(dir, 'real-file.json'), 'x\n');
    await symlink('real-file.json', path.join(dir, 'CLAUDE.md'));
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({
        version: 1,
        existingFiles: [],
        absentAtBackup: [],
        createdFiles: ['CLAUDE.md'],
      }),
    );

    const report = await new HardeningScanner().rollback(dir);

    expect(
      report.unremoved.map((u) => u.path),
      'a legacy entry that could not be resolved vanished from the report entirely',
    ).toContain('CLAUDE.md');
  });

  /**
   * The retention rule differs from `unrestored`'s, deliberately: the backup
   * holds no copy of a generated file, so keeping the directory buys nothing —
   * and keeping it would feed the wedge #338 is about.
   */
  it('does not retain the backup for an unremoved generated file', async () => {
    await writeFile(path.join(dir, 'real-file.json'), 'x\n');
    await symlink('real-file.json', path.join(dir, 'CLAUDE.md'));
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({ version: 1, existingFiles: [], absentAtBackup: [], createdFiles: ['CLAUDE.md'] }),
    );

    const report = await new HardeningScanner().rollback(dir);

    expect(report.unremoved.length, 'the fixture did not produce an unremoved entry').toBe(1);
    expect(
      report.backupRetainedAt,
      'a backup holding no copy of anything was kept, which is what wedges the next run',
    ).toBeUndefined();
    expect(await exists(backup)).toBe(false);
  });

  /**
   * CONTROL — a rollback with nothing to report still completes. Correct on the
   * previous build too; here so "report everything" cannot become "never
   * complete", which would make every rollback exit 1.
   */
  it('still reports a clean rollback as complete', async () => {
    await writeFile(path.join(dir, 'generated.json'), 'x\n');
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: [],
        absentAtBackup: [],
        createdFiles: [{ path: 'generated.json', sha256: createHash('sha256').update('x\n').digest('hex') }],
      }),
    );

    const report = await new HardeningScanner().rollback(dir);

    expect(report.removed).toContain('generated.json');
    // `?? []` so this stays a CONTROL: it must pass on the build that has no
    // `unremoved` channel at all, or it is a second regression test dressed as
    // one and cannot tell a loosened rule from a missing field.
    expect(report.unremoved ?? [], 'a clean rollback reported an exception').toEqual([]);
    expect(report.unrestored ?? []).toEqual([]);
  });
});

describe('#347.1/#347.3 the guards that decide a refusal are observed by something', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-347-'));
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /**
   * #347.3 — `createBackup` wrapped its probe in `identityOrUndefined`,
   * collapsing the three-valued result back into two and throwing away exactly
   * the distinction #333 added it for. An EACCES, ELOOP or EIO on the directory
   * `mkdir` had just returned was reported as `HMA-BACKUP-VANISHED — disappeared
   * immediately after being created`: a claim about the filesystem that only
   * ENOENT supports.
   *
   * Asserted at the decision rather than through `createBackup`, because the
   * window between `mkdir` and `stat` is not something a test can hold open.
   */
  it('separates a proven absence from a refused probe', () => {
    expect(backupIdentityOrThrow({ kind: 'identity', id: { dev: 1, ino: 2 } }, '/b'))
      .toEqual({ dev: 1, ino: 2 });

    let vanished: NodeJS.ErrnoException | undefined;
    try { backupIdentityOrThrow({ kind: 'absent' }, '/b'); } catch (e) { vanished = e as NodeJS.ErrnoException; }
    expect(vanished?.code, 'a proven absence is no longer reported as one').toBe('HMA-BACKUP-VANISHED');

    let refused: NodeJS.ErrnoException | undefined;
    try { backupIdentityOrThrow({ kind: 'unknown' }, '/b'); } catch (e) { refused = e as NodeJS.ErrnoException; }
    expect(
      refused?.code,
      'a probe the filesystem refused is reported as the directory having vanished, '
      + 'which only ENOENT supports',
    ).toBe('HMA-BACKUP-UNIDENTIFIED');
    expect(refused?.message, 'the message repeats the claim the code no longer makes')
      .not.toContain('disappeared');
  });

  /**
   * #347.1 — the "an unreadable probe refuses" clause survived mutation against
   * the WHOLE suite: mutating it to `return false` and running all 2601 tests
   * gave a byte-identical result. The behaviour was correct at runtime and
   * nothing observed it, and by this project's own rule surviving mutation means
   * untested.
   *
   * That clause is gone with #341 — the predicate no longer reads the tree at
   * all — so this asserts its replacement: the archive check is three-valued, and
   * an ancestor the filesystem will not describe leaves the question open rather
   * than answering "not an archive", which at the write gate authorises the
   * write.
   *
   * A basename over NAME_MAX makes `stat` fail with ENAMETOOLONG: a real errno
   * from a real filesystem, no mocking.
   */
  it('leaves the archive question open when an ancestor cannot be examined', async () => {
    const scanner = new HardeningScanner() as unknown as {
      isInsideArchiveBase(p: string, targetDir: string): Promise<'yes' | 'no' | 'unknown'>;
    };
    const base = path.join(dir, '.hackmyagent-backup', '2026-01-01-000000-000-abcdabcd');
    await mkdir(base, { recursive: true });

    expect(
      await scanner.isInsideArchiveBase(path.join(dir, 'a'.repeat(300), 'config.json'), dir),
      'an ancestor the filesystem would not describe was answered "not an archive", '
      + 'which is the direction that authorises rewriting a backup',
    ).toBe('unknown');

    // Both controls, or "unknown" could be the only answer this ever gives.
    expect(
      await scanner.isInsideArchiveBase(path.join(base, 'config.json'), dir),
      'a file really inside the backup base was not recognised',
    ).toBe('yes');
    expect(
      await scanner.isInsideArchiveBase(path.join(dir, 'vendor', 'config.json'), dir),
      'an ordinary file was called an archive',
    ).toBe('no');
  });
});
