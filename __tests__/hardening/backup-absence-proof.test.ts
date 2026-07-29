/**
 * #313 — `createBackup` inferred absence from any errno.
 *
 * The candidate loop was `try { access; copyFile; existingFiles.push } catch {
 * absentAtBackup.push }`, which collapses ENOENT-of-target, EACCES, ELOOP,
 * EISDIR, ENOSPC and EMFILE into "the file isn't there". `absentAtBackup` is the
 * list `recordCreatedFiles` draws from, so anything that merely FAILED to copy
 * became eligible to be reported as HMA-generated and deleted by `rollback`.
 *
 * Measured on the exact case `isGenuinelyAbsent`'s own docstring describes:
 *
 *   proj/.gitignore -> ./nowhere        (a dangling symlink the USER placed)
 *   secure --fix ; rollback
 *     absentAtBackup has .gitignore : true
 *     createdFiles                  : ['.gitignore']
 *     "Rollback complete / Restored 2 modified files, removed 2 generated files."
 *     user's .gitignore symlink survived? NO
 *     HMA's actual creation ./nowhere left behind? YES
 *
 * #304 replaced this inference with an lstat proof in `ensureBackupCovers`, but
 * left the identical inference here — and because `ctx.covered` is pre-seeded
 * from `absentAtBackup`, that proof was never consulted for any of the 25 static
 * candidates. The comment #304 added, "Both lists are OBSERVATIONS, never
 * inferences", was therefore false when it was written.
 *
 * The classification has THREE outcomes, so all three are enumerated here — the
 * previous round's lesson was that the case the fix was not imagined against is
 * the case that ships. Both failure fixtures are uid-independent (a dangling
 * symlink and a directory-where-a-file-is-expected) rather than chmod-based,
 * because a chmod fixture silently stops testing anything when run as root.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

interface Manifest {
  existingFiles: string[];
  absentAtBackup: string[];
  absentAtFixWrite?: string[];
  createdFiles: { path: string }[];
}

describe('#313 backup classification proves absence, never infers it', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'hma-313-'));
    writeFileSync(join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
    // A real fixable finding, so `--fix` has work to do and a backup is made.
    writeFileSync(join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
  });

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const runFix = async (): Promise<Manifest> => {
    await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const backupRoot = join(dir, '.hackmyagent-backup');
    const stamps = readdirSync(backupRoot);
    expect(stamps.length, 'no backup directory was created; the run made no fixes').toBe(1);
    return JSON.parse(
      readFileSync(join(backupRoot, stamps[0], '.manifest.json'), 'utf8'),
    ) as Manifest;
  };

  it('records a genuinely absent candidate as absent', async () => {
    // The positive case the list exists for. Without this, "never in
    // absentAtBackup" passes by never classifying anything.
    const manifest = await runFix();
    expect(
      manifest.absentAtBackup,
      'nothing was classified absent; the other assertions here are vacuous',
    ).not.toHaveLength(0);
    expect(manifest.absentAtBackup).toContain('.gitignore');
  });

  it('records a copyable existing candidate as existing', async () => {
    writeFileSync(join(dir, '.gitignore'), 'node_modules\n');
    const manifest = await runFix();
    expect(manifest.existingFiles).toContain('.gitignore');
    expect(manifest.absentAtBackup).not.toContain('.gitignore');
  });

  it('classifies a dangling symlink as NEITHER absent nor backed up', async () => {
    // The entry exists — the user put it there — and it has no recoverable
    // copy. `existingFiles` would lie about restorability; `absentAtBackup`
    // would let rollback delete it.
    symlinkSync('./nowhere', join(dir, '.gitignore'));
    const manifest = await runFix();

    expect(
      manifest.absentAtBackup,
      'a dangling symlink the user placed was recorded as absent, which makes it '
      + 'eligible to be reported as HMA-generated and deleted (#313)',
    ).not.toContain('.gitignore');
    expect(
      manifest.existingFiles,
      'a file with no recoverable copy was recorded as restorable',
    ).not.toContain('.gitignore');
  });

  it('classifies a directory-where-a-file-is-expected as NEITHER', async () => {
    // EISDIR rather than ENOENT: `access` passes, `copyFile` fails. Same class,
    // a different errno, and uid-independent.
    mkdirSync(join(dir, '.gitignore'));
    const manifest = await runFix();
    expect(manifest.absentAtBackup).not.toContain('.gitignore');
    expect(manifest.existingFiles).not.toContain('.gitignore');
  });

  it('treats an lstat that fails for a NON-ENOENT reason as not-absent', async () => {
    // `isGenuinelyAbsent` claims in its own docstring that an lstat failing for
    // any other reason "proves nothing, so it is not a creation either". Every
    // fixture above reaches that function through a SUCCESSFUL lstat — a
    // dangling symlink and a directory both stat fine — so the catch branch,
    // where the fail-safe actually lives, was never executed.
    //
    // `.claude/settings.json` is a nested candidate, so making `.claude` a
    // regular file makes lstat itself raise ENOTDIR. Uid-independent, unlike a
    // chmod fixture.
    writeFileSync(join(dir, '.claude'), 'i am a regular file, not a directory\n');
    const manifest = await runFix();

    expect(
      manifest.absentAtBackup,
      'an ENOTDIR from lstat was read as proof of absence, making the path '
      + 'eligible for deletion at rollback (#313)',
    ).not.toContain('.claude/settings.json');
    expect(manifest.existingFiles).not.toContain('.claude/settings.json');
  });

  it('does not delete the user\'s dangling symlink at rollback', async () => {
    // The end-to-end harm, asserted on the filesystem rather than on the
    // manifest: the previous behaviour printed a clean revert while removing it.
    symlinkSync('./nowhere', join(dir, '.gitignore'));
    await runFix();

    const report = await new HardeningScanner().rollback(dir);

    expect(
      existsSync(join(dir, '.gitignore')) || lstatSync(join(dir, '.gitignore'), { throwIfNoEntry: false }),
      'rollback deleted a symlink the user created, and reported a clean revert',
    ).toBeTruthy();
    expect(lstatSync(join(dir, '.gitignore')).isSymbolicLink()).toBe(true);
    expect(report.removed).not.toContain('.gitignore');
  });

  it('refuses the fix write when the candidate cannot be backed up', async () => {
    // A path in neither list is not `covered`, so `ensureBackupCovers` has to
    // run for it, fail to prove absence, and refuse — leaving the user's bytes.
    // Without this the classification could be correct while the write still
    // landed unrecoverably.
    const original = 'ORIGINAL_CONTENT_MUST_SURVIVE\n';
    mkdirSync(join(dir, 'sub'));
    writeFileSync(join(dir, 'sub', 'keep.txt'), original);
    // `.gitignore` as a directory: GIT-001 wants to write it, and it cannot be
    // copied, so the write must be abandoned rather than attempted.
    mkdirSync(join(dir, '.gitignore'));

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(
      lstatSync(join(dir, '.gitignore')).isDirectory(),
      'the fix wrote over a path it could not back up',
    ).toBe(true);
    expect(
      result.findings.some((f) => f.checkId === 'FIX-WRITE-FAILED'),
      'the refused write was silent; a failed fix must be reported',
    ).toBe(true);
  });
});
