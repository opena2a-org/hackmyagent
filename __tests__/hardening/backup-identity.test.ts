/**
 * #317 / #318 / #320 / #321 — the backup directory is recognised by filesystem
 * IDENTITY, and it is created provably new.
 *
 * Four rounds of this subsystem shipped a guard that was a STRING describing the
 * backup directory, and each round the attacker changed the string without
 * changing the directory:
 *
 *   #304  a `\`-folded path            #305  the directory NAME
 *   #309  the manifest SHAPE           #317  a case-sensitive resolve-prefix compare
 *
 * The tests here are written against the ROOT rather than against the four
 * fixtures, so a fifth spelling has nowhere to land:
 *
 *   - the copy HMA makes must still hold the ORIGINAL bytes after `--fix`,
 *     however the backup directory's path is spelled;
 *   - the run's own backup must be a directory nothing in the tree could have
 *     created first;
 *   - `rollback` must not read or write through a symlink at either end.
 *
 * Filesystem coverage is deliberate. The case-variant fixture can only
 * reproduce on a case-insensitive filesystem (the macOS default, where #317 was
 * measured); on a case-sensitive one the two names are simply two directories.
 * So it asserts a filesystem-independent invariant, plus a stronger claim about
 * the mechanism when the filesystem is measured to fold case.
 *
 * #329 — the sentence that used to sit here claimed the same root was covered on
 * every filesystem by `symlinked to a sibling inside the tree` below. It is not:
 * that test asserts `FIX-BACKUP-FAILED`, which is `prepareBackupRoot` refusing
 * before any backup exists, so there is no `backupContext` in the run and
 * `backupIdent` is never read. Measured consequence: replacing `sameIdentity`
 * with `return false` — deleting the whole mechanism — left this file and
 * `backup-archive-integrity` green under a NON-symlinked TMPDIR, which is
 * exactly ubuntu-latest. The lexical fast path succeeds whenever
 * `realpath(target) === target`, so identity is never consulted there.
 *
 * `identity survives a scan root that is a symlink` below is the case that does
 * reach it, on any filesystem, by making the two spellings differ.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { lstat, mkdir, mkdtemp, readdir, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;
const BODY = `${JSON.stringify({ github: FAKE_GH_TOKEN }, null, 2)}\n`;

const BACKUP = '.hackmyagent-backup';

/** Measured, never assumed: does this filesystem fold case? */
async function foldsCase(dir: string): Promise<boolean> {
  const probe = path.join(dir, '.hma-case-probe');
  await mkdir(probe);
  try {
    await stat(path.join(dir, '.HMA-CASE-PROBE'));
    return true;
  } catch {
    return false;
  } finally {
    await rm(probe, { recursive: true, force: true });
  }
}

/** Every file under `root`, target-relative, so a copy can be found by name. */
async function walkFiles(root: string, rel = ''): Promise<string[]> {
  const out: string[] = [];
  let entries;
  try {
    entries = await readdir(path.join(root, rel), { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const child = path.join(rel, e.name);
    if (e.isDirectory()) out.push(...(await walkFiles(root, child)));
    else if (e.isFile()) out.push(child);
  }
  return out;
}

describe('backup directory identity', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-identity-'));
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /**
   * #317 — the measured attack. One pre-existing `.HACKMYAGENT-BACKUP`, no
   * symlink, no traversal, no forged manifest: `mkdir` adopted it, `readdir`
   * returned the original casing, the case-SENSITIVE prefix compare said the
   * copy was not inside the run's backup, and `--fix` redacted its own backup.
   */
  it('does not redact its own backup when the base directory differs only in case', async () => {
    const folds = await foldsCase(dir);
    await mkdir(path.join(dir, '.HACKMYAGENT-BACKUP'));
    await writeFile(path.join(dir, 'config.json'), BODY);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    // Non-vacuity: the fix must have LANDED. If `--fix` did nothing, "the backup
    // still holds the original" says only that no backup was written.
    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'the live file was not redacted, so this run never exercised the backup path',
    ).not.toContain(FAKE_GH_TOKEN);
    expect(result.findings.some((f) => f.checkId === 'CRED-001')).toBe(true);

    const copies = (await walkFiles(dir)).filter(
      (f) => path.basename(f) === 'config.json' && f !== 'config.json',
    );
    expect(copies.length, 'no backup copy of config.json was made at all').toBeGreaterThan(0);
    for (const copy of copies) {
      expect(
        await readFile(path.join(dir, copy), 'utf-8'),
        `${copy} was redacted, so the original credential bytes are unrecoverable`,
      ).toContain(FAKE_GH_TOKEN);
    }

    if (folds) {
      // Where the filesystem folds case, prove the mechanism was exercised: the
      // adopted directory is the pre-existing UPPERCASE one.
      expect(
        copies.some((c) => c.startsWith('.HACKMYAGENT-BACKUP' + path.sep)),
        'the case-variant directory was not adopted, so the #317 mechanism was not reached',
      ).toBe(true);
    }
  });

  /**
   * #317 — the consequence the user actually sees. The redaction was restored
   * behind `[+] Rollback complete / restored config.json`.
   */
  it('recovers the original bytes on rollback through a case-variant base', async () => {
    await mkdir(path.join(dir, '.HACKMYAGENT-BACKUP'));
    await writeFile(path.join(dir, 'config.json'), BODY);

    const scanner = new HardeningScanner();
    await scanner.scan({ targetDir: dir, autoFix: true });
    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'the live file was not redacted, so the rollback under test reverts nothing',
    ).not.toContain(FAKE_GH_TOKEN);

    const report = await scanner.rollback(dir);

    expect(report.restored, 'rollback reported no restore').toContain('config.json');
    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'rollback restored the redacted copy and reported a clean revert',
    ).toBe(BODY);
  });

  /**
   * The same defect as #317 reached without case folding, so it bites on every
   * filesystem: `.hackmyagent-backup` symlinked to a sibling directory inside
   * the tree. Before the fix, `mkdir -p` and `copyFile` followed the link, the
   * copies landed under a path the guard was not comparing against, and `--fix`
   * rewrote them. Now the base is refused outright — wherever it points — and no
   * fix lands without a backup.
   */
  it('refuses a backup base symlinked to a sibling inside the tree', async () => {
    await mkdir(path.join(dir, 'real-backup'));
    await symlink(path.join(dir, 'real-backup'), path.join(dir, BACKUP));
    await writeFile(path.join(dir, 'config.json'), BODY);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'the fix landed even though the backup base was a symlink',
    ).toBe(BODY);
    expect(result.findings.some((f) => f.checkId === 'FIX-BACKUP-FAILED')).toBe(true);
    expect(
      (await walkFiles(path.join(dir, 'real-backup'))).length,
      'copies were written through the symlink',
    ).toBe(0);
  });

  /**
   * #321 — the same refusal, pointed out of the tree. Measured before the fix:
   * `.env` bytes, credential included, landed in `/attacker/drop`.
   */
  it('refuses a backup base symlinked out of the tree, and writes nothing there', async () => {
    const drop = await mkdtemp(path.join(tmpdir(), 'hma-identity-drop-'));
    try {
      await symlink(drop, path.join(dir, BACKUP));
      await writeFile(path.join(dir, '.env'), `GITHUB_TOKEN=${FAKE_GH_TOKEN}\n`);
      await writeFile(path.join(dir, 'config.json'), BODY);

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      expect((await walkFiles(drop)).length, 'backup copies were exfiltrated out of the tree').toBe(0);
      expect(
        await readFile(path.join(dir, 'config.json'), 'utf-8'),
        'a fix landed with no recoverable backup',
      ).toBe(BODY);
      // The user is told why, rather than left with a silent detect-only run.
      const failed = result.findings.find((f) => f.checkId === 'FIX-BACKUP-FAILED');
      expect(failed, 'the run degraded to detect-only without saying so').toBeDefined();
    } finally {
      await rm(drop, { recursive: true, force: true });
    }
  });

  /**
   * The remedy has to match the CAUSE.
   *
   * Refusing a symlinked backup base added a new reason for `FIX-BACKUP-FAILED`,
   * and the finding described every reason as a permission problem: "make the
   * target writable", over guidance blaming a read-only mount, a container volume
   * or a checkout owned by another user. None of that is true here, and making a
   * symlink writable changes nothing — the user is sent to look at the wrong
   * thing while their fixes stay unapplied.
   */
  it('tells the user the backup base is a symlink, not that the tree is read-only', async () => {
    const drop = await mkdtemp(path.join(tmpdir(), 'hma-identity-cause-'));
    try {
      await symlink(drop, path.join(dir, BACKUP));
      await writeFile(path.join(dir, 'config.json'), BODY);

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const failed = result.findings.find((f) => f.checkId === 'FIX-BACKUP-FAILED');

      expect(failed, 'the run degraded to detect-only without saying so').toBeDefined();
      const text = `${failed!.message} ${failed!.fix ?? ''} ${failed!.guidance ?? ''}`;
      expect(text, 'the finding never mentions the actual cause').toContain('symbolic link');
      expect(
        failed!.fix ?? '',
        'the fix line tells the user to make the target writable, which does not fix a symlink',
      ).not.toContain('writable');
      expect(
        failed!.guidance ?? '',
        'the guidance blames a read-only mount for a cause that has nothing to do with permissions',
      ).not.toContain('read-only mount');
      // Names the thing to act on, literally.
      expect(failed!.fix ?? '').toContain(BACKUP);
    } finally {
      await rm(drop, { recursive: true, force: true });
    }
  });

  /**
   * #320 — the stamp was a UTC second and the `mkdir` was recursive, so the tree
   * could name HMA's own backup by guessing. Measured in the #320 report: 125
   * pre-seeded stamps, 126 CRED-001 detect-only vs 125 under `--fix`, and the
   * score moved UP. (This stack's own reproduction used 90 stamps and saw 91 vs
   * 90; the two runs are reported separately rather than averaged — #334.)
   *
   * Seeds a WINDOW around the current second so the run cannot dodge the fixture
   * by landing on an unseeded second.
   */
  it('never adopts a pre-seeded stamp directory as its own backup', async () => {
    const now = Date.now();
    const seeded: string[] = [];
    for (let offset = -2; offset <= 4; offset++) {
      const stamp = new Date(now + offset * 1000)
        .toISOString()
        .slice(0, 19)
        .replace('T', '-')
        .replace(/:/g, '');
      const seedDir = path.join(dir, BACKUP, stamp);
      await mkdir(seedDir, { recursive: true });
      await writeFile(path.join(seedDir, 'config.json'), BODY);
      seeded.push(stamp);
    }
    await writeFile(path.join(dir, 'config.json'), BODY);

    const detect = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const detectCount = detect.findings.filter((f) => f.checkId === 'CRED-001').length;
    expect(detectCount, 'the seeded credentials were not detected at all').toBe(seeded.length + 1);

    const fixDir = await mkdtemp(path.join(tmpdir(), 'hma-identity-fix-'));
    try {
      const { cp } = await import('node:fs/promises');
      await cp(dir, fixDir, { recursive: true });
      const fixed = await new HardeningScanner().scan({ targetDir: fixDir, autoFix: true });
      // #374 — this run reports the copy in its OWN archive too, so the count is
      // taken over everything that is not that. Excluding by the flag, not by
      // subtracting one: if a pre-seeded stamp were adopted, its credential would
      // vanish from this same list, which is the defect being measured. A count
      // that allowed one extra finding would hide an adoption by one.
      const fixCount = fixed.findings.filter(
        (f) => f.checkId === 'CRED-001' && !f.inOwnArchive,
      ).length;

      expect(
        fixCount,
        'a pre-seeded stamp directory was adopted as this run\'s backup, so its '
        + 'credential was silently dropped under --fix',
      ).toBe(detectCount);

      // Non-vacuity for the exclusion above: this run really did archive a copy
      // and really did attribute it to itself. Without this, a build where
      // `inOwnArchive` is never set would satisfy the count for the wrong reason.
      expect(
        fixed.findings.filter((f) => f.checkId === 'CRED-001' && f.inOwnArchive).length,
        'this run\'s own archive was never attributed, so the filter above excluded nothing',
      ).toBeGreaterThan(0);

      // And every seeded copy still holds its original bytes.
      for (const stamp of seeded) {
        expect(
          await readFile(path.join(fixDir, BACKUP, stamp, 'config.json'), 'utf-8'),
        ).toBe(BODY);
      }
    } finally {
      await rm(fixDir, { recursive: true, force: true });
    }
  });

  /**
   * #329 — the case that actually reaches the identity mechanism, on every
   * filesystem.
   *
   * `isOwnBackupDir` tries a lexical compare first and only asks the filesystem
   * when that fails. On a plain Linux `/tmp` — ubuntu-latest — `realpath(target)
   * === target`, so the lexical compare always succeeds and identity is never
   * consulted: replacing `sameIdentity` with `return false` left every suite in
   * this file green there.
   *
   * Scanning THROUGH a symlink to the root makes the two spellings differ:
   * `prepareBackupRoot` resolves the target, so `backupContext.backupDir` is
   * spelled with the real path while the walk produces paths spelled with the
   * link. Nothing lexical can match, and the only thing that can recognise the
   * run's own backup is its `dev`+`ino`.
   *
   * The measured consequence when it cannot: the copy `--fix` has just written
   * is scanned as if it were a second exposure, so one credential is reported
   * twice and the score drops for a file the user does not have.
   *
   * The fixture carries the case-variant base as well, so on a case-folding
   * filesystem it reproduces against the pre-identity commit too — there the
   * adopted directory is spelled one way and read back another. On a
   * case-sensitive filesystem that half is inert and the symlinked root carries
   * the test on its own.
   */
  it('identity survives a scan root that is a symlink', async () => {
    const link = path.join(path.dirname(dir), `${path.basename(dir)}-link`);
    await symlink(dir, link);
    try {
      await mkdir(path.join(dir, '.HACKMYAGENT-BACKUP'));
      await writeFile(path.join(dir, 'config.json'), BODY);

      const result = await new HardeningScanner().scan({ targetDir: link, autoFix: true });
      const cred = result.findings.filter((f) => f.checkId === 'CRED-001');

      // Non-vacuity, both directions: the credential must have been found, and
      // the fix must have landed — otherwise "exactly one finding" would be
      // satisfied by a run that did nothing.
      expect(cred.length, 'no credential was detected through the symlinked root').toBeGreaterThan(0);
      expect(
        await readFile(path.join(dir, 'config.json'), 'utf-8'),
        'the live file was not redacted, so no backup copy was made to recognise',
      ).not.toContain(FAKE_GH_TOKEN);

      const copies = (await walkFiles(dir)).filter(
        (f) => path.basename(f) === 'config.json' && f !== 'config.json',
      );
      expect(copies.length, 'no backup copy was made at all').toBeGreaterThan(0);

      // #374 CHANGED THE OBSERVABLE HERE, and the property is unchanged.
      //
      // This used to assert `cred.length === 1`: the copy `--fix` had just made
      // must not be reported, because recognising it is what identity is for.
      // Since #374 the copy IS reported — every later scan of that tree reports
      // it, and the `--fix` run exempting itself is what made it announce a score
      // its own next scan contradicted.
      //
      // So "did identity resolve?" needs an observable that survives the copy
      // being reported, and there is a better one than a count: the copy is
      // ATTRIBUTED to this run. That attribution runs through
      // `isInsideOwnBackup` -> `sameIdentity`, and on this fixture the lexical
      // shortcut cannot fire — the walk spells paths with the link while
      // `backupContext.backupDir` is spelled with the real path — so the flag is
      // reachable ONLY via `dev`+`ino`. Replacing `sameIdentity` with
      // `return false` turns this assertion red, which is the exact mutation the
      // docstring above says every other suite in this file survives.
      const archived = cred.filter((f) => f.inOwnArchive);
      const live = cred.filter((f) => !f.inOwnArchive);

      expect(
        archived.length,
        'the copy `--fix` had just made was reported WITHOUT being recognised as '
        + 'this run\'s own: the run did not identify its own backup through a path '
        + 'spelled differently, which is what filesystem identity is for',
      ).toBeGreaterThan(0);
      for (const f of archived) {
        // Case-folded deliberately: this fixture pre-creates the archive base as
        // `.HACKMYAGENT-BACKUP` so a case-insensitive filesystem adopts it at
        // that spelling. Asserting the lowercase form here would fail for the
        // very reason the fixture exists, and asserting a spelling at all is the
        // habit this whole file replaced with identity — so this is a sanity
        // check on the flag's target, not the identity assertion itself.
        expect(
          (f.file ?? '').toLowerCase(),
          'a finding was attributed to the archive but is not in it',
        ).toContain('.hackmyagent-backup');
      }

      // And the live file is still reported exactly once, on its own path — the
      // half of the original assertion that is unaffected.
      expect(
        live.length,
        'the live file\'s credential is no longer reported exactly once',
      ).toBe(1);
      expect(
        live[0].file,
        'the reported credential is the backup copy rather than the live file',
      ).toBe('config.json');
    } finally {
      await rm(link, { force: true });
    }
  });

  describe('#318 rollback resolves both ends', () => {
    const seedForgedBackup = async (
      root: string,
      manifest: Record<string, unknown>,
    ): Promise<string> => {
      // `9999-…` sorts above every real stamp, so it is always the one selected.
      const backupDir = path.join(root, BACKUP, '9999-99-99-999999');
      await mkdir(backupDir, { recursive: true });
      await writeFile(path.join(backupDir, '.manifest.json'), JSON.stringify(manifest));
      return backupDir;
    };

    /**
     * The measured #318: `evil/sshlink -> /home/victim/.ssh` plus
     * `existingFiles: ["sshlink/authorized_keys"]` wrote the attacker's bytes to
     * the victim's directory and printed `restored sshlink/authorized_keys`.
     * #312's guard checked `destPath` lexically and then copied THROUGH it.
     */
    it('does not write through a symlinked destination component', async () => {
      const victim = await mkdtemp(path.join(tmpdir(), 'hma-identity-victim-'));
      try {
        await symlink(victim, path.join(dir, 'sshlink'));
        const backupDir = await seedForgedBackup(dir, {
          version: 2,
          existingFiles: ['sshlink/authorized_keys'],
          absentAtBackup: [],
          createdFiles: [],
        });
        await mkdir(path.join(backupDir, 'sshlink'), { recursive: true });
        await writeFile(path.join(backupDir, 'sshlink', 'authorized_keys'), 'PWNED\n');

        const report = await new HardeningScanner().rollback(dir);

        expect(
          (await readdir(victim)).length,
          'rollback wrote outside the tree through a symlinked directory component',
        ).toBe(0);
        expect(report.restored).not.toContain('sshlink/authorized_keys');
      } finally {
        await rm(victim, { recursive: true, force: true });
      }
    });

    /**
     * The mirror image, which #312's reasoning also denied: a symlink INSIDE the
     * backup copies out-of-tree CONTENT IN. Measured before the fix — the bytes
     * of a file outside the tree appeared inside it.
     */
    it('does not restore from a symlinked source inside the backup', async () => {
      const outside = await mkdtemp(path.join(tmpdir(), 'hma-identity-outside-'));
      try {
        const secret = path.join(outside, 'secret');
        await writeFile(secret, 'OUT-OF-TREE-SECRET\n');
        const backupDir = await seedForgedBackup(dir, {
          version: 2,
          existingFiles: ['pulled-in.txt'],
          absentAtBackup: [],
          createdFiles: [],
        });
        await symlink(secret, path.join(backupDir, 'pulled-in.txt'));

        const report = await new HardeningScanner().rollback(dir);

        let landed = true;
        try {
          await lstat(path.join(dir, 'pulled-in.txt'));
        } catch {
          landed = false;
        }
        expect(landed, 'out-of-tree content was copied into the tree').toBe(false);
        expect(report.restored).not.toContain('pulled-in.txt');
      } finally {
        await rm(outside, { recursive: true, force: true });
      }
    });

    /**
     * The `..` half #312 did close. Pinned so the resolved guards cannot be
     * mistaken for a replacement of the lexical one — both are load-bearing, and
     * the lexical check is what keeps a traversal from ever reaching a syscall.
     */
    it('still refuses a .. traversal in the manifest', async () => {
      const backupDir = await seedForgedBackup(dir, {
        version: 2,
        existingFiles: ['../../escaped.txt'],
        absentAtBackup: [],
        createdFiles: [],
      });
      await writeFile(path.join(backupDir, 'payload'), 'TRAVERSAL\n');

      const report = await new HardeningScanner().rollback(dir);

      expect(report.restored).not.toContain('../../escaped.txt');
      let escaped = true;
      try {
        await lstat(path.join(dir, '..', '..', 'escaped.txt'));
      } catch {
        escaped = false;
      }
      expect(escaped, 'a .. traversal in the manifest wrote outside the tree').toBe(false);
    });

    /**
     * The LEAF, not a directory component.
     *
     * Resolving the destination's parent says nothing about the final component,
     * and `copyFile` follows a symlink at the leaf just as happily. The
     * symlinked-component test above exercises the parent; this exercises the
     * entry itself, which is a separate enforcement in the same guard and had no
     * failing case of its own.
     */
    it('does not write through a symlink at the destination leaf', async () => {
      const victim = await mkdtemp(path.join(tmpdir(), 'hma-identity-leaf-'));
      try {
        const target = path.join(victim, 'outside.json');
        await writeFile(target, 'ORIGINAL-OUTSIDE-CONTENT\n');
        // The leaf inside the tree is a link pointing out of it.
        await symlink(target, path.join(dir, 'config.json'));

        const backupDir = await seedForgedBackup(dir, {
          version: 2,
          existingFiles: ['config.json'],
          absentAtBackup: [],
          createdFiles: [],
        });
        await writeFile(path.join(backupDir, 'config.json'), 'PAYLOAD\n');

        const report = await new HardeningScanner().rollback(dir);

        expect(
          await readFile(target, 'utf-8'),
          'rollback wrote through a symlinked leaf and overwrote a file outside the tree',
        ).toBe('ORIGINAL-OUTSIDE-CONTENT\n');
        expect(report.restored).not.toContain('config.json');
      } finally {
        await rm(victim, { recursive: true, force: true });
      }
    });

    /**
     * A backup entry that is not a regular file.
     *
     * `copyFile` on a FIFO blocks in `open()` until a writer appears, so a named
     * pipe shipped in a cloned repo's `.hackmyagent-backup/9999-…/` and listed in
     * its manifest hangs `rollback` indefinitely. The `isFile()` check is what
     * makes that a refusal instead of a stall, and the timeout on this test is
     * what gives the assertion teeth: against the unguarded loop it does not fail,
     * it never returns.
     */
    it('refuses a backup source that is not a regular file, instead of blocking on it', async () => {
      const backupDir = await seedForgedBackup(dir, {
        version: 2,
        existingFiles: ['pipe'],
        absentAtBackup: [],
        createdFiles: [],
      });
      const { execFileSync } = await import('node:child_process');
      execFileSync('mkfifo', [path.join(backupDir, 'pipe')]);

      const report = await new HardeningScanner().rollback(dir);

      expect(report.restored, 'a FIFO was treated as a restorable file').not.toContain('pipe');
      let landed = true;
      try {
        await lstat(path.join(dir, 'pipe'));
      } catch {
        landed = false;
      }
      expect(landed, 'a non-regular backup entry was copied into the tree').toBe(false);
    }, 15_000);

    /**
     * "I could not check whether this is a symlink" must not become "it is not
     * one". #313 was that inference on an errno; this is the same inference in a
     * new place, so the guard is pinned directly.
     *
     * Tested through a stubbed `lstat` rather than a fixture on purpose: every
     * non-ENOENT errno reachable on a real filesystem here (ENAMETOOLONG is the
     * only one that can be produced, since the parent has already been resolved)
     * makes the FOLLOWING syscall fail the same way, so a black-box fixture
     * cannot tell the two implementations apart. The inference is still wrong,
     * and the next caller of this helper may not be a `copyFile`.
     */
    it('refuses a destination whose leaf cannot be checked for being a symlink', async () => {
      // #347.4 — the helper now says WHY it refused, so this asserts the cause
      // rather than a bare null. A single null could not distinguish "a symlink
      // stands here" from "the filesystem would not answer", and one sentence
      // was printed for both.
      type Outcome = { ok: true; path: string } | { ok: false; cause: string };
      const resolve = (scannerUnderTest: HardeningScanner) =>
        (scannerUnderTest as unknown as {
          resolveInsideTree(
            targetReal: string,
            rel: string,
            opts: { followLeafLink: boolean },
          ): Promise<Outcome>;
        }).resolveInsideTree;
      const scanner = new HardeningScanner();
      // The helper's contract is a RESOLVED target. On macOS `os.tmpdir()` sits
      // under `/var -> /private/var`, so passing the unresolved path makes every
      // call return null — which is what the control assertion below is for.
      const targetReal = await realpath(dir);

      // A basename over NAME_MAX. `lstat` fails with ENAMETOOLONG, which is a
      // real errno from a real filesystem and proves nothing about whether the
      // entry is a symlink — no mocking needed.
      const tooLong = 'a'.repeat(300);
      expect(
        await resolve(scanner).call(scanner, targetReal, tooLong, { followLeafLink: true }),
        'an lstat failure that proves nothing was read as "not a symlink"',
      ).toEqual({ ok: false, cause: 'leaf-unexaminable' });

      // Control: the same helper must still resolve an ordinary entry, or the
      // assertion above would pass on a helper that refuses everything.
      await writeFile(path.join(dir, 'ordinary.json'), '{}\n');
      expect(
        (await resolve(scanner).call(scanner, targetReal, 'ordinary.json', { followLeafLink: true })).ok,
        'the helper refuses a legitimate path, so the assertion above means nothing',
      ).toBe(true);

      // And absence is still fine — restoring a file the user deleted is the
      // whole point of a rollback.
      expect(
        (await resolve(scanner).call(scanner, targetReal, 'deleted-since-backup.json', { followLeafLink: true })).ok,
        'a file absent from the tree can no longer be restored',
      ).toBe(true);
    });

    /**
     * A forged `createdFiles` entry aimed through a symlink is a DELETE outside
     * the tree — the same defect as the restore loop with the arrow reversed.
     * The hash has to match, and the manifest supplies BOTH the path and the
     * hash, so the attacker only needs to know the target's contents.
     */
    it('does not unlink through a symlinked destination component', async () => {
      const victim = await mkdtemp(path.join(tmpdir(), 'hma-identity-victim-del-'));
      try {
        const doomed = path.join(victim, 'keep-me');
        const contents = 'CONTENTS THE ATTACKER KNOWS\n';
        await writeFile(doomed, contents);
        const { createHash } = await import('node:crypto');
        const sha256 = createHash('sha256').update(contents).digest('hex');

        await symlink(victim, path.join(dir, 'link'));
        await seedForgedBackup(dir, {
          version: 2,
          existingFiles: [],
          absentAtBackup: [],
          createdFiles: [{ path: 'link/keep-me', sha256 }],
        });

        const report = await new HardeningScanner().rollback(dir);

        expect(
          (await readFile(doomed, 'utf-8')),
          'rollback deleted a file outside the tree through a symlink',
        ).toBe(contents);
        expect(report.removed).not.toContain('link/keep-me');
      } finally {
        await rm(victim, { recursive: true, force: true });
      }
    });
  });
});
