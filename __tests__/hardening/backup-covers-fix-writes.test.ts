/**
 * #300 — `secure --fix` must not rewrite a file the backup cannot restore.
 *
 * The backup candidate set was a static root-relative list (`BACKUP_FILES`)
 * predicted before the scan, while the set of files a fix WRITES is decided
 * during it. Every widening of detection therefore widened the write set
 * without widening the restorable set. #292 widened CRED-001 to config-shaped
 * files at any depth, and this shipped:
 *
 *   before   config/production.json + src/config.json  = a live token
 *   --fix    both -> ${GITHUB_TOKEN}
 *   backup   holds only package.json
 *   rollback "Restored 1 modified file", exit 0
 *   after    both still redacted — the original bytes are gone
 *
 * Irreversible data loss behind an explicit success message.
 *
 * The whole suite stayed green through it, because the existing backup tests
 * assert that a backup directory exists and that the ROOT candidates are in
 * it. Both remained true. So the assertion here is round-trip recovery of the
 * actual bytes — fix, then rollback, then compare against what was on disk
 * before — which is the property a user relies on and the only one that
 * fails when coverage lags detection.
 *
 * Credential values are synthesised at runtime from a repeated character,
 * never written as literals, so nothing here trips a secret scanner.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, access, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { BackupManifest } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'d'.repeat(36)}`;

async function withTree(
  files: Record<string, string>,
  body: (dir: string) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-300-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(path.join(dir, path.dirname(rel)), { recursive: true });
      await writeFile(path.join(dir, rel), content);
    }
    await body(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function readAll(dir: string, rels: string[]): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const rel of rels) out[rel] = await readFile(path.join(dir, rel), 'utf-8');
  return out;
}

async function latestManifest(dir: string): Promise<BackupManifest> {
  const base = path.join(dir, '.hackmyagent-backup');
  const { readdir } = await import('node:fs/promises');
  const stamps = (await readdir(base)).sort();
  const raw = await readFile(path.join(base, stamps[stamps.length - 1], '.manifest.json'), 'utf-8');
  return JSON.parse(raw) as BackupManifest;
}

const PKG = '{"name":"backup-fixture","version":"1.0.0"}\n';

describe('#300 every fix write is covered by the backup', () => {
  describe('credential fixes below the scan root', () => {
    // The exact placements #292 taught CRED-001 to reach. Each one was an
    // unrecoverable rewrite.
    const nested = {
      'package.json': PKG,
      'config/production.json': JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
      'src/config.json': JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
    };
    const targets = ['config/production.json', 'src/config.json'];

    it('restores the original bytes of a nested config after rollback', async () => {
      await withTree(nested, async (dir) => {
        const before = await readAll(dir, targets);

        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

        // Non-vacuity: if --fix did not actually rewrite these, the round
        // trip below is trivially satisfied and proves nothing.
        const afterFix = await readAll(dir, targets);
        for (const rel of targets) {
          expect(
            afterFix[rel],
            `--fix left ${rel} untouched; this test is measuring nothing`,
          ).not.toBe(before[rel]);
        }

        await new HardeningScanner().rollback(dir);

        const afterRollback = await readAll(dir, targets);
        for (const rel of targets) {
          expect(
            afterRollback[rel],
            `${rel} was rewritten by --fix and rollback could not restore it — `
            + 'the backup does not cover what the fix writes (#300)',
          ).toBe(before[rel]);
        }
      });
    });

    it('reports the restore honestly instead of claiming success over one file', async () => {
      await withTree(nested, async (dir) => {
        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
        const report = await new HardeningScanner().rollback(dir);
        for (const rel of targets) {
          expect(
            report.restored,
            `rollback reported success without naming ${rel}`,
          ).toContain(rel);
        }
      });
    });

    it('records the nested paths in the manifest, not just the root candidates', async () => {
      await withTree(nested, async (dir) => {
        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
        const manifest = await latestManifest(dir);
        for (const rel of targets) {
          expect(
            manifest.existingFiles,
            `${rel} was rewritten but never entered the manifest, so a rollback `
            + 'in a later process has nothing to restore from',
          ).toContain(rel);
        }
      });
    });
  });

  describe('gateway config fixes', () => {
    // `.openclaw/config.json` is a gateway fix target but was never a
    // BACKUP_FILES entry (the list has bare `openclaw.json`), and this write
    // site bypassed `applyFixWrite` entirely — the same defect reached by a
    // second code path, at the scan root rather than below it.
    const gateway = {
      'package.json': PKG,
      '.openclaw/config.json': JSON.stringify({ gateway: { host: '0.0.0.0', port: 8080 } }) + '\n',
    };

    it('restores the original bytes of a gateway config after rollback', async () => {
      await withTree(gateway, async (dir) => {
        const rel = '.openclaw/config.json';
        const before = await readAll(dir, [rel]);

        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

        const afterFix = await readAll(dir, [rel]);
        expect(
          afterFix[rel],
          'the gateway fix did not rewrite the config; this test is measuring nothing',
        ).not.toBe(before[rel]);

        await new HardeningScanner().rollback(dir);

        expect(
          (await readAll(dir, [rel]))[rel],
          'the gateway fix rewrote a config the backup does not cover (#300)',
        ).toBe(before[rel]);
      });
    });
  });

  describe('fail-safe direction', () => {
    it('abandons the write rather than writing what it cannot undo', async () => {
      await withTree({ 'package.json': PKG, 'config.json': '{"a":1}\n' }, async (dir) => {
        const scanner = new HardeningScanner();
        const target = path.join(dir, 'config.json');
        const before = await readFile(target, 'utf-8');

        // No backup context: this is the state after a `createBackup`
        // failure, which already downgrades the run to detect-only. A write
        // here would be unrevertable by construction.
        const landed = await (scanner as unknown as {
          applyFixWrite(f: string, c: string): Promise<boolean>;
        }).applyFixWrite(target, '{"a":2}\n');

        expect(landed, 'a fix wrote with no backup context behind it').toBe(false);
        expect(
          await readFile(target, 'utf-8'),
          'the file was rewritten even though nothing could restore it',
        ).toBe(before);
      });
    });

    it('does not let one run\'s backup authorise the next run\'s writes', async () => {
      await withTree({ 'package.json': PKG, 'config.json': '{"a":1}\n' }, async (dir) => {
        const scanner = new HardeningScanner();
        await scanner.scan({ targetDir: dir, autoFix: true });
        // Same instance, a detect-only run: the backup context from the
        // previous run must not survive into it.
        await scanner.scan({ targetDir: dir, autoFix: false });

        const target = path.join(dir, 'config.json');
        const before = await readFile(target, 'utf-8');
        const landed = await (scanner as unknown as {
          applyFixWrite(f: string, c: string): Promise<boolean>;
        }).applyFixWrite(target, '{"a":3}\n');

        expect(landed, 'a stale backup context authorised a write').toBe(false);
        expect(await readFile(target, 'utf-8')).toBe(before);
      });
    });
  });
});

/**
 * #304 — the #300 guard protected a normalized DESCRIPTION of the path, not
 * the path being written.
 *
 * `toTargetRelativePath` folded `\` to `/` "for Windows". On POSIX `\` is an
 * ordinary filename byte, so the derived key no longer round-tripped to the
 * file it named, and every consumer downstream inherited that:
 *
 *   - `ensureBackupCovers` copied from `path.join(targetDir, rel)`, which
 *     resolved elsewhere; `copyFile` raised ENOENT; the catch read that as
 *     "nothing to copy, so this is a creation" and returned TRUE — authorising
 *     the very write it exists to gate. Reproduced: `we\ird/config.json`
 *     rewritten, absent from the backup, rollback exit 0 "Restored 2 modified
 *     files", original bytes unrecoverable.
 *   - two DIFFERENT files (`we\ird/…` and `we/ird/…`) collided onto one key,
 *     so one file's backup held the other's bytes.
 *   - the mangled key was appended to `absentAtBackup`, the list whose
 *     membership authorises a rollback-time `unlink`.
 *
 * Fixed at the layer: `path.join`/`path.relative` are already platform-correct,
 * so the manual rewriting is gone. Absence is now PROVEN with `lstat` against
 * the real path instead of inferred from an errno, and write-time absences are
 * recorded separately from backup-time ones.
 *
 * The assertion is round-trip recovery of the actual bytes, per file. A test
 * that a backup directory exists, or that SOME file was restored, stays green
 * through all of the above.
 */
describe('#304 coverage is keyed on the path being written', () => {
  const BS = 'we\\ird/config.json';   // a literal backslash in the directory name
  const FS_ = 'we/ird/config.json';   // collides with BS under the old folding

  it('restores a config whose path contains a backslash', async () => {
    await withTree({
      'package.json': PKG,
      [BS]: JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
    }, async (dir) => {
      const before = await readAll(dir, [BS]);

      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      // Non-vacuity: the round trip proves nothing if --fix never wrote here.
      expect(
        (await readAll(dir, [BS]))[BS],
        '--fix left the backslash path untouched; this test is measuring nothing',
      ).not.toBe(before[BS]);

      await new HardeningScanner().rollback(dir);

      expect(
        (await readAll(dir, [BS]))[BS],
        'a path containing a backslash was rewritten with no recoverable copy, '
        + 'and rollback reported success anyway (#304)',
      ).toBe(before[BS]);
    });
  });

  it('keeps two paths that differ only by separator byte apart', async () => {
    await withTree({
      'package.json': PKG,
      [BS]: JSON.stringify({ token: FAKE_GH_TOKEN, which: 'backslash' }) + '\n',
      [FS_]: JSON.stringify({ token: FAKE_GH_TOKEN, which: 'realdir' }) + '\n',
    }, async (dir) => {
      const before = await readAll(dir, [BS, FS_]);
      // Guard the fixture itself: if these two ever hold identical bytes the
      // collision below is undetectable and the test silently stops working.
      expect(before[BS], 'fixture collision — the two files must differ')
        .not.toBe(before[FS_]);

      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      for (const rel of [BS, FS_]) {
        expect(
          (await readAll(dir, [rel]))[rel],
          `--fix left ${rel} untouched; this test is measuring nothing`,
        ).not.toBe(before[rel]);
      }

      await new HardeningScanner().rollback(dir);

      // Each must come back as ITSELF. Sharing one manifest key restored one
      // file's bytes over the other and lost the difference silently.
      for (const rel of [BS, FS_]) {
        expect(
          (await readAll(dir, [rel]))[rel],
          `${rel} did not round-trip to its own bytes — two distinct files `
          + 'shared one backup key (#304)',
        ).toBe(before[rel]);
      }
    });
  });

  it('classifies an existing file as existing, never as one it generated', async () => {
    await withTree({
      'package.json': PKG,
      [BS]: JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
    }, async (dir) => {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const manifest = await latestManifest(dir);

      expect(
        manifest.existingFiles,
        'a file that was on disk before the run is missing from `existingFiles`, '
        + 'so rollback has nothing to restore it from',
      ).toContain(BS);

      // The unlink hazard. `createdFiles` membership is what licenses rollback
      // to DELETE a path, and it is fed from the proven-absent lists. A file
      // the user wrote must never reach it.
      expect(
        manifest.createdFiles.map(c => c.path),
        'a pre-existing user file was recorded as HMA-generated; rollback '
        + 'would delete it outright instead of restoring it (#304)',
      ).not.toContain(BS);
      expect(manifest.absentAtBackup).not.toContain(BS);
      expect(manifest.absentAtFixWrite ?? []).not.toContain(BS);
    });
  });

  /**
   * The guard's own seam. The three round-trip tests above pin the reported
   * defect, but they cannot reach two of the branches the fix adds, because
   * with the path key honest again `path.join(targetDir, rel)` and `filePath`
   * name the same file and `copyFile` simply succeeds. These drive the branches
   * directly — the same technique the fail-safe block above already uses — so
   * the ENOENT classification and the write-time provenance are not left as
   * unguarded code.
   */
  describe('absence is proven, not inferred', () => {
    /** Establish a real backup context, then hand back the write seam. */
    async function armed(dir: string) {
      const scanner = new HardeningScanner();
      await scanner.scan({ targetDir: dir, autoFix: true });
      const base = path.join(dir, '.hackmyagent-backup');
      const stamps = (await readdir(base)).sort();
      return {
        backupPath: path.join(base, stamps[stamps.length - 1]),
        applyFixWrite: (f: string, c: string) => (scanner as unknown as {
          applyFixWrite(f: string, c: string): Promise<boolean>;
        }).applyFixWrite(f, c),
        recordCreatedFiles: (t: string, b: string, c: string[]) =>
          scanner.recordCreatedFiles(t, b, c),
      };
    }

    it('treats a dangling symlink as an entry that exists, not as a creation', async () => {
      await withTree({ 'package.json': PKG, 'config.json': '{"a":1}\n' }, async (dir) => {
        const link = path.join(dir, 'dangling.json');
        await symlink(path.join(dir, 'absent-target.json'), link);

        const { applyFixWrite } = await armed(dir);

        // `copyFile` FOLLOWS the link, so it raises ENOENT even though the
        // link itself is right there. Reading that errno as "nothing to copy,
        // therefore a creation" is what #304 was: the write gets authorised
        // with nothing to restore from, and rollback would then delete a
        // symlink the user placed.
        const landed = await applyFixWrite(link, '{"a":2}\n');

        expect(
          landed,
          'a write was authorised through a link whose target could not be '
          + 'copied — the backup cannot undo it (#304)',
        ).toBe(false);
        await expect(
          access(path.join(dir, 'absent-target.json')),
          'the fix wrote THROUGH the dangling link, creating a file no backup covers',
        ).rejects.toThrow();
      });
    });

    it('records a created file that was never a static backup candidate', async () => {
      await withTree({ 'package.json': PKG, 'config.json': '{"a":1}\n' }, async (dir) => {
        // Not in `BACKUP_FILES`, so `createBackup` never observed it and it
        // reaches `absentAtBackup` through no route at all. This is the shape
        // every detection widening produces (#298 is queued behind it): the
        // fix creates a path the static candidate list never predicted.
        const generated = path.join(dir, 'deep', 'nested', 'generated.json');
        await mkdir(path.dirname(generated), { recursive: true });

        const { backupPath, applyFixWrite, recordCreatedFiles } = await armed(dir);

        expect(
          await applyFixWrite(generated, '{"generated":true}\n'),
          'a creation below the candidate list was refused',
        ).toBe(true);

        const rel = path.relative(dir, generated);
        const seen = JSON.parse(
          await readFile(path.join(backupPath, '.manifest.json'), 'utf-8'),
        ) as BackupManifest;
        expect(
          seen.absentAtFixWrite ?? [],
          'a write-time absence was not recorded under its own provenance',
        ).toContain(rel);

        await recordCreatedFiles(dir, backupPath, [generated]);

        const after = JSON.parse(
          await readFile(path.join(backupPath, '.manifest.json'), 'utf-8'),
        ) as BackupManifest;
        expect(
          after.createdFiles.map(c => c.path),
          'a file the fix demonstrably generated was not recorded as created, '
          + 'so rollback leaves it behind while reporting a clean revert',
        ).toContain(rel);
      });
    });
  });
});
