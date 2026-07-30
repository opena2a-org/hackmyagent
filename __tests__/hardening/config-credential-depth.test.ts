/**
 * #292 — credential detection for config-shaped files was root-only.
 *
 * The same GitHub token scored 69/100 with CRED-001 at `./config.json` and
 * 96/100 with NO credential finding at `src/config.json`, `sub/config.json` or
 * `config/production.json`, because `checkCredentialExposure` probed a fixed
 * list of `path.join(targetDir, name)` paths. A conventional layout therefore
 * passed clean. Code files were never affected — the AST layer covers those at
 * any depth (AST-CRED-001/003) — so the gap was specific to config-shaped
 * files below the scan root.
 *
 * These tests run the scanner in-process (no spawn) so they are fast and can
 * be mutation-checked cheaply. Credential values are synthesised at runtime
 * from a repeated character, never written as literals, so nothing here trips
 * GitHub push protection or a secret scanner.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

/**
 * Write a backup that is genuinely HMA's own: a timestamped directory with a
 * manifest of the shape `createBackup` produces, holding copies of files that
 * exist in `projectDir`. Returns the path of the first copy.
 *
 * #305 — the exclusion is keyed on those two properties, so a fixture that
 * only *looks* like a backup is (correctly) scanned like any other directory.
 */
async function seedRealBackup(
  projectDir: string,
  copies: Record<string, string>,
): Promise<string> {
  const backupDir = path.join(projectDir, '.hackmyagent-backup', '2026-01-01-000000');
  await mkdir(backupDir, { recursive: true });
  await writeFile(
    path.join(backupDir, '.manifest.json'),
    JSON.stringify({
      version: 2,
      existingFiles: Object.keys(copies),
      absentAtBackup: [],
      createdFiles: [],
    }, null, 2),
  );
  let first = '';
  for (const [rel, body] of Object.entries(copies)) {
    const dest = path.join(backupDir, rel);
    await mkdir(path.dirname(dest), { recursive: true });
    await writeFile(dest, body);
    if (!first) first = dest;
  }
  return first;
}

async function scanTreeWithConfigAt(relPath: string) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-292-'));
  try {
    await mkdir(path.join(dir, path.dirname(relPath)), { recursive: true });
    await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
    await writeFile(path.join(dir, relPath), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: dir, autoFix: false });
    const cred = result.findings.filter(
      (f) => f.checkId === 'CRED-001' && !f.passed
    );
    return { result, cred };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('#292 config-shaped credential detection below the scan root', () => {
  // Each of these was a silent 96/100 "no credential finding" before the fix.
  const nestedPlacements = [
    'sub/config.json',
    'src/config.json',
    'deep/a/b/settings.json',
    'config/production.json', // config-shaped by LOCATION, not by filename
    'conf/db.yaml',
  ];

  for (const rel of nestedPlacements) {
    it(`detects a credential at ${rel}`, async () => {
      const { cred } = await scanTreeWithConfigAt(rel);
      expect(
        cred.length,
        `no CRED-001 for a token at ${rel} — the root-only probe regressed`
      ).toBeGreaterThan(0);
    });

    it(`names ${rel} as the finding location, not just the basename`, async () => {
      const { cred } = await scanTreeWithConfigAt(rel);
      // A finding that cannot say WHERE the credential is fails CISO Rule 11.
      expect(cred.map((f) => f.file)).toContain(rel);
    });
  }

  it('still detects a credential at the scan root (no coverage lost)', async () => {
    const { cred } = await scanTreeWithConfigAt('config.json');
    expect(cred.length).toBeGreaterThan(0);
    expect(cred.map((f) => f.file)).toContain('config.json');
  });

  it('scores a nested credential the same as a root one', async () => {
    const root = await scanTreeWithConfigAt('config.json');
    const nested = await scanTreeWithConfigAt('src/config.json');
    // The whole point of #292: placement must not change the verdict.
    expect(nested.result.score).toBe(root.result.score);
  });

  it('does not fire on a non-config file inside a config directory', async () => {
    // `config/README.md` sits in a config dir but is not structured config.
    // Guards the location rule from becoming "anything under config/".
    const { cred } = await scanTreeWithConfigAt('config/README.md');
    expect(cred.map((f) => f.file)).not.toContain('config/README.md');
  });

  it('does not double-report the backup THIS RUN just created', async () => {
    // `createBackup` runs before every check, so without an exclusion the same
    // run reports the credential twice: once in the live file and once in the
    // copy HMA made microseconds earlier. The exclusion is `backupContext
    // .backupDir` — a path HMA chose this run, which nothing in the scanned
    // tree can name (#309).
    //
    // The fixture deliberately does NOT pre-seed a backup: the archive under
    // test has to be one this run produced, or the test is measuring the
    // pre-existing-archive case below instead.
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-292-bak-'));
    try {
      const body = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
      await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
      await writeFile(path.join(dir, 'config.json'), body);

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const cred = result.findings.filter((f) => f.checkId === 'CRED-001');

      // Non-vacuity: the live original must fire, or "no backup findings" is
      // just "the walk found nothing anywhere".
      expect(
        cred.some((f) => f.file === 'config.json'),
        'the live config never fired; this test is measuring nothing',
      ).toBe(true);
      expect(
        cred.filter((f) => f.file?.includes('.hackmyagent-backup')),
        'the run reported the copy it had just made itself',
      ).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  /**
   * #326 — this asserted that the archive remediation `rm -rf <path>` quoted its
   * argument. There is no such remediation any more: nothing keyed on a
   * `.hackmyagent-backup` NAME may claim HackMyAgent created the directory or
   * offer to delete it, because the name and the manifest are both files in the
   * scanned tree.
   *
   * What has to hold instead is asserted here: a project path that would have
   * broken the quoting produces no destructive command at all, and the finding
   * is still actionable. The quoting property itself did not disappear with the
   * citation — it moved to the report that still emits an `rm`, where
   * `__tests__/cli/report-render-safety.test.ts` round-trips the emitted
   * argument through a real shell.
   */
  it('emits no destructive command for an archive, whatever the path contains', async () => {
    const parent = await mkdtemp(path.join(tmpdir(), 'hma-quote-'));
    const dir = path.join(parent, "it's a project");
    try {
      await mkdir(dir, { recursive: true });
      await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
      await writeFile(path.join(dir, 'config.json'), '{"note":"already remediated"}\n');
      await seedRealBackup(dir, {
        'config.json': JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
      });

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const archived = result.findings.find(
        (f) => f.checkId === 'CRED-001' && f.file?.includes('.hackmyagent-backup'),
      );
      expect(archived, 'the archived credential was not reported').toBeDefined();

      expect(
        archived!.fix,
        'a destructive command was emitted for a directory HackMyAgent cannot prove it created',
      ).not.toContain('rm ');
      // Still not a dead end: the finding says what to do and how to check.
      expect(archived!.fix, 'the finding has no path forward').toBeTruthy();
      expect(archived!.guidance ?? '', 'the finding never names the verify step').toContain('secure');
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  it('REPORTS a pre-existing archive, and never rewrites it', async () => {
    // #309 reversed the previous expectation here, so the reason is recorded
    // rather than the assertion quietly flipped.
    //
    // The old test asserted that a genuine pre-existing backup produced NO
    // findings, on the theory that it duplicated the live file. That theory is
    // false after a `--fix`: the live file then holds `${GITHUB_TOKEN}` and the
    // archive holds the ONLY remaining plaintext copy of the secret. It is not
    // a duplicate of anything, and suppressing it meant hiding a plaintext
    // credential that HMA itself created. Worse, the predicate that decided
    // "this really is a backup" read the scanned tree — a name, then a name
    // plus a 70-byte manifest plus an existence probe — so it was forgeable
    // three rounds running.
    //
    // The write hazard is real and is now gated separately, on its own: `--fix`
    // refuses to write into an archive. That assertion is unchanged, and is the
    // one that actually protects the user's bytes.
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-292-bak2-'));
    try {
      const backupBody = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
      await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
      await writeFile(path.join(dir, 'config.json'), '{"note":"already remediated"}\n');
      const backupCopy = await seedRealBackup(dir, { 'config.json': backupBody });

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const archived = result.findings.filter(
        (f) => f.checkId === 'CRED-001' && f.file?.includes('.hackmyagent-backup'),
      );

      expect(
        archived.length,
        'the plaintext secret left behind in HMA\'s own archive was not reported',
      ).toBeGreaterThan(0);

      // Not a dead end: `secure --fix` is the one command that cannot resolve
      // this, so it must not be the offered remedy.
      expect(archived[0].fixable).toBe(false);
      expect(archived[0].fix).not.toContain('secure --fix');
      // #326 — the fix names the ACTION, and the guidance names the directory
      // by its name rather than by a path HackMyAgent would then offer to
      // delete. Asserting on the guidance keeps the "says which directory this
      // is about" property without the citation that carried it.
      expect(archived[0].guidance ?? '').toContain('.hackmyagent-backup');

      const { readFile } = await import('node:fs/promises');
      expect(
        await readFile(backupCopy, 'utf-8'),
        '--fix rewrote the backup copy; rollback would restore redacted content'
      ).toBe(backupBody);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('never treats a backup directory BELOW the scan root as a scan target', async () => {
    // #302 — the exclusion above was `rel.startsWith('.hackmyagent-backup/')`,
    // and `rel` is relative to the SCAN ROOT. So it recognised a backup
    // directory only at that exact root, and scanning one level up walked
    // back into it as `child/.hackmyagent-backup/…`. Every consequence the
    // test above guards against returned, one directory higher:
    //
    //   secure child --fix    child/.hackmyagent-backup/…/config.json = the token
    //   secure PARENT --fix   that same copy is now ${GITHUB_TOKEN}
    //   rollback child        exit 0, restores the redacted bytes
    //
    // Not an exotic invocation — `secure ~/projects` over a tree where any
    // one project has been secured before.
    const parent = await mkdtemp(path.join(tmpdir(), 'hma-302-'));
    try {
      const child = path.join(parent, 'child');
      await mkdir(child, { recursive: true });
      await writeFile(path.join(parent, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
      await writeFile(path.join(child, 'package.json'), '{"name":"c","version":"1.0.0"}\n');

      const backupBody = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
      // A live config beside it, so the scan has real work to do here and the
      // assertion is not just "the walk found nothing at all". It is also the
      // file the backup copy mirrors, which is what makes the copy redundant.
      await writeFile(path.join(child, 'config.json'), backupBody);
      const backupCopy = await seedRealBackup(child, { 'config.json': backupBody });

      const result = await new HardeningScanner().scan({ targetDir: parent, autoFix: true });

      // Non-vacuity: the scan must have reached the child and fired there.
      expect(
        result.findings.some((f) => f.checkId === 'CRED-001' && f.file === 'child/config.json'),
        'the parent scan never reached the child; this test is measuring nothing',
      ).toBe(true);

      // #309 — the child's archive is a foreign archive to this run, so it is
      // reported like any other directory holding a plaintext secret. What must
      // NOT happen is the parent scan REWRITING it, which is the harm #302 was
      // filed for and is asserted below.
      const { readFile } = await import('node:fs/promises');
      expect(
        await readFile(backupCopy, 'utf-8'),
        'the parent scan rewrote the CHILD\'s backup; the child\'s rollback now '
        + 'restores redacted content over redacted content',
      ).toBe(backupBody);
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  describe('#305 the exclusion is keyed on the artifact, not on its name', () => {
    // The exclusion above was `is any ancestor directory NAMED
    // .hackmyagent-backup`, and the scanned tree is attacker-controlled. So the
    // NAME was a one-word suppression token. Reproduced with identical bytes
    // and only the directory name differing:
    //
    //   lib/.notabackup/config.json          69/100, 2 CRED-001 CRITICAL, exit 1
    //   lib/.hackmyagent-backup/config.json  96/100, silent,              exit 0
    //
    // That is the same 69 -> 96 suppression as the `${...}` brace bypass this
    // release calls unacceptable, so it gets the same answer.
    async function scanWithCredIn(relDir: string, opts: { manifest: boolean; live: boolean }) {
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-305-'));
      try {
        const body = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
        await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
        await mkdir(path.join(dir, relDir), { recursive: true });
        await writeFile(path.join(dir, relDir, 'config.json'), body);
        if (opts.manifest) {
          await writeFile(
            path.join(dir, relDir, '.manifest.json'),
            JSON.stringify({ version: 2, existingFiles: [], absentAtBackup: [], createdFiles: [] }),
          );
        }
        // A benign live file at the path this copy would be a backup OF, so
        // the counterpart half of the guard is satisfied without planting a
        // second credential (which would fire on its own and make the
        // assertions below pass for the wrong reason).
        if (opts.live) {
          await mkdir(path.join(dir, 'lib'), { recursive: true });
          await writeFile(path.join(dir, 'lib', 'config.json'), '{"note":"not a secret"}\n');
        }
        const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        return result.findings.filter((f) => f.checkId === 'CRED-001' && !f.passed);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    }

    const NAMED = 'lib/.hackmyagent-backup/2026-01-01-000000';
    const CONTROL = 'lib/.notabackup/2026-01-01-000000';

    it('detects a credential under a directory merely NAMED like a backup', async () => {
      const cred = await scanWithCredIn(NAMED, { manifest: false, live: false });
      expect(
        cred.length,
        'a directory called .hackmyagent-backup suppressed a real credential — '
        + 'the exclusion is a token the scanned tree can type (#305)',
      ).toBeGreaterThan(0);
    });

    it('scores the forged name exactly like any other directory', async () => {
      // The control is the same tree with one word changed. Comparing the two
      // is what makes this a suppression test rather than a detection test:
      // any divergence IS the bypass.
      const named = await scanWithCredIn(NAMED, { manifest: false, live: false });
      const control = await scanWithCredIn(CONTROL, { manifest: false, live: false });
      expect(control.length, 'the control fixture did not fire; nothing is being compared')
        .toBeGreaterThan(0);
      expect(named.length).toBe(control.length);
    });

    /**
     * The SECOND consumer of the same forgeable name. `findFilesMatching`
     * skipped the whole directory by name, and it feeds seven checks — `.env`,
     * `SOUL.md`, session files, daemon configs, `memory.json`, `openclaw.json`
     * — so the token hid considerably more than config-shaped credentials.
     * Fixing only the walk that the issue was reported against would have left
     * this one live.
     */
    async function scanForEnvIn(relDir: string) {
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-305-env-'));
      try {
        await writeFile(path.join(dir, 'package.json'), '{"name":"e","version":"1.0.0"}\n');
        await mkdir(path.join(dir, relDir), { recursive: true });
        await writeFile(
          path.join(dir, relDir, '.env'),
          `ANTHROPIC_API_KEY=sk-ant-api03-${'z'.repeat(24)}\n`,
        );
        const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        return result.findings.filter((f) => !f.passed && f.file?.includes(path.basename(relDir)));
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    }

    it('still finds a nested .env under a directory merely NAMED like a backup', async () => {
      const named = await scanForEnvIn('lib/.hackmyagent-backup');
      const control = await scanForEnvIn('lib/.notabackup');
      expect(control.length, 'the control fixture did not fire; nothing is being compared')
        .toBeGreaterThan(0);
      expect(
        named.length,
        'a directory named .hackmyagent-backup hid a plaintext .env from the '
        + 'file-discovery walk that feeds seven separate checks (#305)',
      ).toBe(control.length);
    });

    it('detects a credential under a backup-shaped directory with no manifest', async () => {
      // The other half of the guard. Here the copy DOES mirror a live file, so
      // the counterpart test alone would clear it — only the missing manifest
      // says this is not something HMA wrote. Both halves are load-bearing.
      const cred = await scanWithCredIn(NAMED, { manifest: false, live: true });
      expect(
        cred.some((f) => f.file?.includes('.hackmyagent-backup')),
        'a directory with no manifest was accepted as an HMA backup purely '
        + 'because a same-named live file existed beside it (#305)',
      ).toBe(true);
    });

    it('detects a credential under a forged manifest that mirrors nothing', async () => {
      // A valid manifest alone is still forgeable — anyone can write one. What
      // makes a backup a backup is that it is a COPY, so a "backup" of a file
      // that does not exist in the live tree is scanned like any other file.
      const cred = await scanWithCredIn(NAMED, { manifest: true, live: false });
      expect(
        cred.length,
        'writing a plausible .manifest.json was enough to suppress detection (#305)',
      ).toBeGreaterThan(0);
    });

    /**
     * #309 — THE QUADRANT THAT WAS THE BYPASS.
     *
     * The #305 tests above ran three of the four combinations of
     * {manifest} x {live counterpart} and every one of them passed. The fourth,
     * both-true, was the one the guard was designed around, so it was the one
     * never asserted — and it restored the full suppression:
     *
     *   .notabackup          69/100, CRED-001 CRITICAL, exit 1
     *   .hackmyagent-backup  96/100, silent,            exit 0
     *
     * on identical credential bytes. The forged half costs 70 bytes of JSON and
     * a benign decoy file. So the whole 2x2 is enumerated here rather than the
     * cases the fix was built for, and each case is compared against a control
     * tree that differs by one word in a directory name — any divergence at all
     * IS the bypass, whatever the reasoning behind it.
     */
    for (const manifest of [false, true]) {
      for (const live of [false, true]) {
        it(`is unaffected by the directory name: manifest=${manifest} live=${live}`, async () => {
          const named = await scanWithCredIn(NAMED, { manifest, live });
          const control = await scanWithCredIn(CONTROL, { manifest, live });
          expect(
            control.length,
            'the control fixture did not fire; nothing is being compared',
          ).toBeGreaterThan(0);
          expect(
            named.length,
            `manifest=${manifest} live=${live}: the .hackmyagent-backup name changed `
            + 'the verdict, so it is still a suppression token the scanned tree can type',
          ).toBe(control.length);
        });
      }
    }

    it('suppression cannot be bought with a dangling-symlink counterpart', async () => {
      // No decoy needed at all: `lstat` says the entry exists, and the config
      // walk skips symlinks, so the counterpart was never read or reported.
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-309-sym-'));
      try {
        const { symlink } = await import('node:fs/promises');
        await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
        await mkdir(path.join(dir, NAMED), { recursive: true });
        await writeFile(
          path.join(dir, NAMED, 'config.json'),
          JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
        );
        await writeFile(
          path.join(dir, NAMED, '.manifest.json'),
          JSON.stringify({ version: 2, existingFiles: [], absentAtBackup: [], createdFiles: [] }),
        );
        await mkdir(path.join(dir, 'lib'), { recursive: true });
        await symlink('./nowhere-at-all', path.join(dir, 'lib', 'config.json'));

        const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        expect(
          result.findings.filter((f) => f.checkId === 'CRED-001' && !f.passed).length,
          'a dangling symlink was accepted as proof the copy mirrored a live file (#309)',
        ).toBeGreaterThan(0);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    /**
     * #314 — the write guard, asserted at the layer that enforces it.
     *
     * Every auto-fix write goes through `applyFixWrite`, so that is where "never
     * rewrite a backup archive" belongs. It is deliberately NOT reachable end to
     * end today: CRED-001 skips the attempt before it gets here (so the finding
     * can carry a remediation that works instead of a refusal), and every other
     * fix-capable discovery is either root-relative or skips hidden directories.
     * That was verified caller by caller, not assumed.
     *
     * An unreachable guard is exactly the kind of thing that rots into a no-op,
     * so it is exercised directly rather than left to an end-to-end path that
     * does not exist. #309 widened detection INTO archives, which is what makes
     * this the layer that has to hold if any future check gains a recursive
     * walk — the same "fix at the layer" reasoning as #300.
     */
    it('applyFixWrite refuses to write inside a backup archive', async () => {
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-314-write-'));
      try {
        const archive = path.join(dir, '.hackmyagent-backup', '2026-01-01-000000');
        await mkdir(archive, { recursive: true });
        const victim = path.join(archive, 'config.json');
        const original = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
        await writeFile(victim, original);

        // A REAL backup context for this run, with the manifest `ensureBackupCovers`
        // appends to. Without it every write fails at the #300 gate instead, and
        // the control below would agree with the archive case for the wrong
        // reason — which is what the non-vacuity assertion caught.
        const runBackup = path.join(dir, '.hackmyagent-backup', '2026-02-02-000000');
        await mkdir(runBackup, { recursive: true });
        await writeFile(
          path.join(runBackup, '.manifest.json'),
          JSON.stringify({ version: 2, existingFiles: [], absentAtBackup: [], createdFiles: [] }),
        );

        const scanner = new HardeningScanner() as unknown as {
          backupContext?: { backupDir: string; targetDir: string; covered: Set<string> };
          applyFixWrite(p: string, c: string): Promise<boolean>;
        };
        scanner.backupContext = { backupDir: runBackup, targetDir: dir, covered: new Set() };

        const wrote = await scanner.applyFixWrite(victim, 'CLOBBERED\n');
        const { readFile } = await import('node:fs/promises');

        expect(wrote, 'the write into a backup archive was allowed').toBe(false);
        expect(
          await readFile(victim, 'utf-8'),
          'the archive was rewritten; rollback would restore redacted content',
        ).toBe(original);

        // Non-vacuity: the same call on a normal path must succeed, or this is
        // asserting nothing more than "applyFixWrite returns false".
        const ordinary = path.join(dir, 'config.json');
        await writeFile(ordinary, original);
        expect(
          await scanner.applyFixWrite(ordinary, 'REWRITTEN\n'),
          'the control write failed for an unrelated reason; nothing is being compared',
        ).toBe(true);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it('suppression cannot be bought with an ENOTDIR counterpart', async () => {
      // Nothing exists at the counterpart path at all. `lstat` raised ENOTDIR
      // rather than ENOENT, `isGenuinelyAbsent` is fail-SAFE and returned
      // false, and the suppression site read `!absent` as "it exists" — so
      // every non-ENOENT errno silenced a CRITICAL.
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-309-notdir-'));
      try {
        const deep = path.join(dir, 'lib', '.hackmyagent-backup', '2026-01-01-000000', 'sub');
        await mkdir(deep, { recursive: true });
        await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
        await writeFile(
          path.join(deep, 'config.json'),
          JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
        );
        await writeFile(
          path.join(deep, '..', '.manifest.json'),
          JSON.stringify({ version: 2, existingFiles: [], absentAtBackup: [], createdFiles: [] }),
        );
        // `lib/sub` is a FILE, so lstat('lib/sub/config.json') raises ENOTDIR.
        await writeFile(path.join(dir, 'lib', 'sub'), 'i am a regular file\n');

        const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        expect(
          result.findings.filter((f) => f.checkId === 'CRED-001' && !f.passed).length,
          'an ENOTDIR errno was read as "the counterpart exists" and silenced a CRITICAL (#309)',
        ).toBeGreaterThan(0);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  });

  it('treats a nested .env as an env file, not a rewritable config file', async () => {
    // `isEnvFile` keys on basename; a raw `startsWith` on the relative path
    // would classify `sub/.env` as ordinary config and mark it auto-fixable,
    // which means --fix would rewrite the file whose whole purpose is to hold
    // the real value.
    const { cred } = await scanTreeWithConfigAt('sub/.env');
    const envFinding = cred.find((f) => f.file === 'sub/.env');
    expect(envFinding, 'no CRED-001 raised for a nested .env').toBeDefined();
    expect(envFinding?.fixable, 'a nested .env must not be auto-fixable').toBe(false);
  });
});
