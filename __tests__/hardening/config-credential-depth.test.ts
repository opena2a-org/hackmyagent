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

  it('never treats HMA\'s own backup directory as a scan target', async () => {
    // The recursive walk descends into everything except .git/node_modules, and
    // `.hackmyagent-backup/` holds verbatim copies of the files this very check
    // rewrites. Without an explicit exclusion, `--fix` substituted the
    // credential INSIDE the backup, so `rollback` restored already-redacted
    // content and the original was gone — the backup silently stopped being a
    // backup. It also double-counted every finding.
    //
    // #305: the fixture is now a REAL backup — a valid manifest, and a live
    // file that the copy mirrors. Those are the two things that make it HMA's
    // own artifact rather than a directory wearing its name, and suppressing
    // it hides nothing because the live original reports the same finding.
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-292-bak-'));
    try {
      const backupBody = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
      await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
      await writeFile(path.join(dir, 'config.json'), backupBody);
      const backupCopy = await seedRealBackup(dir, { 'config.json': backupBody });

      const scanner = new HardeningScanner();
      const result = await scanner.scan({ targetDir: dir, autoFix: true });

      // Non-vacuity: the live original must fire, or "no backup findings" is
      // just "the walk found nothing anywhere".
      expect(
        result.findings.some((f) => f.checkId === 'CRED-001' && f.file === 'config.json'),
        'the live config never fired; this test is measuring nothing',
      ).toBe(true);

      const backupFindings = result.findings.filter((f) => f.file?.includes('.hackmyagent-backup'));
      expect(backupFindings, 'the backup directory must not produce findings').toEqual([]);

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

      expect(
        result.findings.filter((f) => f.file?.includes('.hackmyagent-backup')),
        'a backup directory one level down produced findings (double-counted)',
      ).toEqual([]);

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
