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
import { HardeningScanner, archiveBaseFromProbe, backupIdentityOrThrow } from '../../src/hardening/scanner';

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

  /**
   * The same inference one level up, found while auditing this change's own
   * diff: `resolveArchiveBase` returned null on ANY failure, and null means "no
   * archive here", which at the write gate is permission to rewrite the file. A
   * tree root the filesystem will not describe would have authorised HackMyAgent
   * to redact a previous run's backup.
   *
   * Only a proven absence is `none`. A refused probe leaves the question open.
   */
  it('leaves the question open when the tree root itself cannot be resolved', async () => {
    const scanner = new HardeningScanner() as unknown as {
      isInsideArchiveBase(p: string, targetDir: string): Promise<'yes' | 'no' | 'unknown'>;
    };
    // A target whose own basename is over NAME_MAX: `realpath` fails
    // ENAMETOOLONG, a real errno that proves nothing about what is there.
    const unresolvable = path.join(dir, 'b'.repeat(300));
    expect(
      await scanner.isInsideArchiveBase(path.join(unresolvable, 'config.json'), unresolvable),
      'a tree root the filesystem would not describe was answered "no archive here", '
      + 'which authorises rewriting a backup',
    ).toBe('unknown');

    // Control: a target that genuinely has no backup base is still a settled
    // "no", or the assertion above would pass on a build that never answers.
    const plain = path.join(dir, 'plain');
    await mkdir(plain, { recursive: true });
    expect(
      await scanner.isInsideArchiveBase(path.join(plain, 'config.json'), plain),
      'a tree with no backup directory refuses to answer, so nothing would ever be fixable',
    ).toBe('no');
  });

  /**
   * M3 — the last clause of the three-valued chain survived mutation. Replacing
   * it with `{ kind: 'none' }` (fail open) left the whole suite green: 203 files,
   * 2615 passed. Its two siblings were covered; this one was not.
   *
   * Asserted at the decision, for the same reason as #347.3: the window between
   * "lstat said directory" and "stat for the identity" cannot be held open.
   */
  it('maps an unreadable identity probe of the base to unknown, not to "no base"', () => {
    expect(archiveBaseFromProbe({ kind: 'identity', id: { dev: 7, ino: 9 } }, '/b'))
      .toEqual({ kind: 'base', real: '/b', ident: { dev: 7, ino: 9 } });
    expect(
      archiveBaseFromProbe({ kind: 'absent' }, '/b'),
      'a proven absence is no longer a proven absence',
    ).toEqual({ kind: 'none' });
    expect(
      archiveBaseFromProbe({ kind: 'unknown' }, '/b'),
      'a refused probe of the backup base was read as "there is no backup here", '
      + 'which at the write gate authorises rewriting one',
    ).toEqual({ kind: 'unknown' });
  });
});

describe('#341 second-order: a fix inside another project\'s backup is disclosed', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-foreign-'));
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /**
   * The residual of #341's decision, which the CHANGELOG claimed was "stated in
   * the test" when no test asserted it. `secure --fix <parent>` rewrites a
   * nested project's archive; `rollback <child>` then restores the redaction
   * over the redaction and reports success. The bytes are recoverable only
   * through `rollback <parent>`, and nothing on screen said so.
   *
   * A changelog sentence is not a disclosure. This asserts the finding.
   */
  it('reports it, on screen, with a command that recovers the bytes', async () => {
    const token = `ghp_${'a'.repeat(36)}`;
    const child = path.join(dir, 'child');
    const childArchive = path.join(child, '.hackmyagent-backup', '2026-01-01-000000-000-abcdabcd');
    await mkdir(childArchive, { recursive: true });
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
    await writeFile(path.join(child, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
    await writeFile(path.join(child, 'config.json'), `{"t":"${token}"}\n`);
    await writeFile(path.join(childArchive, 'config.json'), `{"t":"${token}"}\n`);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    // Non-vacuity: the write really did land inside the child's archive.
    const { readFile } = await import('node:fs/promises');
    expect(
      await readFile(path.join(childArchive, 'config.json'), 'utf-8'),
      'the nested archive was not rewritten, so there is nothing to disclose',
    ).not.toContain(token);

    const disclosure = result.findings.find((f) => f.checkId === 'FIX-FOREIGN-ARCHIVE');
    expect(
      disclosure,
      'a nested project\'s rollback was silently degraded and nothing reported it',
    ).toBeDefined();
    // `passed: false` is what puts it on screen; a passed finding is filtered out,
    // which is how the first version of this disclosure existed and appeared nowhere.
    expect(disclosure!.passed, 'the finding exists but is filtered out of the report').toBe(false);
    expect(disclosure!.fix, 'the disclosure has no command that recovers the bytes')
      .toContain('rollback');
    expect(disclosure!.guidance ?? '').toContain('report success');
  }, 120_000);

  /**
   * CONTROL — an ordinary tree with no nested archive says nothing. Without it
   * the assertion above would pass on a build that emits the note always.
   */
  it('says nothing when no write lands in a nested archive', async () => {
    const token = `ghp_${'a'.repeat(36)}`;
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
    await writeFile(path.join(dir, 'config.json'), `{"t":"${token}"}\n`);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(
      result.findings.some((f) => f.checkId === 'FIX-FOREIGN-ARCHIVE'),
      'an ordinary tree was told its nested project was affected',
    ).toBe(false);
  }, 120_000);
});
