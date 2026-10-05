/**
 * #381 — the gate on the post-fix verify scan did not gate.
 *
 * #374 made `secure --fix` run a second, context-free scan so the score it
 * announces is the score the next scan produces: the next scan walks the archive
 * this run just wrote, and this run's own scan excluded it. The second scan was
 * meant to be skipped when the archive could not move the score, but the gate
 * read `backupContext.covered.size`, and `covered` is seeded from
 * `existingFiles` PLUS `absentAtBackup` — the static candidates that do NOT
 * exist. On an empty directory that is every candidate, so the gate was always
 * true and every `--fix` paid for two full scans.
 *
 * Both directions are pinned, because either alone is insufficient:
 *   1. an archive that received no copy does not trigger the second scan, and
 *      the next scan finds nothing in it that the skipped scan would have added;
 *   2. an archive that DID receive a copy still triggers it when nothing was
 *      fixed — the #374 case the gate exists for.
 * Plus the fail-safe: an archive that cannot be listed counts as holding a copy.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdir, writeFile, rm, readdir, readFile, symlink } from 'node:fs/promises';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

async function onlyArchive(dir: string): Promise<string> {
  const stamps = await readdir(path.join(dir, '.hackmyagent-backup'));
  expect(stamps.length, 'no archive was created, so this run exercised nothing').toBe(1);
  return path.join(dir, '.hackmyagent-backup', stamps[0]);
}

describe('#381 the post-fix verify scan runs only when the archive holds a copy', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('skips the second scan when the archive holds nothing but its manifest', async () => {
    // A tree with nothing to fix and nothing to copy. An empty directory is
    // not one: GIT-001 creates a `.gitignore` there, and a fix that lands runs
    // the verify scan regardless. So the `.gitignore` is a link to a shared one
    // outside the tree — GIT-001 reads through it and passes, and the backup
    // withholds it because it resolves outside the scanned tree.
    const root = tempDir('hma-381-empty-');
    const dir = path.join(root, 'tree');
    try {
      await mkdir(dir);
      await mkdir(path.join(root, 'shared'));
      await writeFile(
        path.join(root, 'shared', '.gitignore'),
        '.env\n.env.*\nsecrets.json\ncredentials.json\n*.pem\n*.key\n.idea/\n.vscode/\nnode_modules/\ndist/\n',
      );
      await symlink(path.join('..', 'shared', '.gitignore'), path.join(dir, '.gitignore'));

      const scan = vi.spyOn(HardeningScanner.prototype, 'scan');
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const scansDuringFix = scan.mock.calls.length;
      vi.restoreAllMocks();

      // ── Non-vacuity ──
      // The archive exists and holds no copy, and the manifest lists absent
      // candidates — the entries that made the old gate true.
      const archive = await onlyArchive(dir);
      expect(await readdir(archive)).toEqual(['.manifest.json']);
      const manifest = JSON.parse(await readFile(path.join(archive, '.manifest.json'), 'utf-8'));
      expect(manifest.existingFiles).toEqual([]);
      expect(manifest.absentAtBackup.length, 'no absent candidates were recorded').toBeGreaterThan(0);
      expect(
        fixed.findings.filter((f) => f.fixed && f.file).map((f) => `${f.checkId} ${f.file}`),
        'a fix landed, so the verify scan runs for that reason and this isolates nothing',
      ).toEqual([]);

      // ── The property ──
      // Fails on the pre-fix build: 2 scans, the second one a full scan of a
      // tree whose archive cannot change the result.
      expect(scansDuringFix, 'an archive with no copy in it triggered a second full scan (#381)').toBe(1);

      // Skipping it must not reopen #374. With no fix to verify, the verify
      // scan's only contribution is the findings it sees inside this run's
      // archive, so the next scan must find none there. (Not `score` equality:
      // the refused write through the link is reported by FIX-WRITE-FAILED,
      // which only the run that attempted it can produce. Measured 93 vs 98
      // with and without the second scan alike.)
      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      expect(
        rescan.findings
          .filter((f) => (f.file ?? '').includes('.hackmyagent-backup'))
          .map((f) => `${f.checkId} ${f.file}`),
        'the next scan reports a finding in an archive the verify scan was skipped for',
      ).toEqual([]);
      expect(fixed.findings.some((f) => f.inOwnArchive)).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('still runs the second scan when the archive holds a copy and nothing was fixed', async () => {
    const dir = tempDir('hma-381-copy-');
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      await writeFile(
        path.join(dir, '.gitignore'),
        '.env\n.env.*\nsecrets.json\ncredentials.json\n*.pem\n*.key\n.idea/\n.vscode/\nnode_modules/\ndist/\n',
      );
      await mkdir(path.join(dir, 'src'), { recursive: true });
      await writeFile(path.join(dir, 'src', 'index.js'), 'module.exports = 1;\n');

      const scan = vi.spyOn(HardeningScanner.prototype, 'scan');
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const scansDuringFix = scan.mock.calls.length;
      vi.restoreAllMocks();

      // ── Non-vacuity ──
      // A copy landed in the archive and no fix landed, so only the archive
      // can be the reason for the second scan.
      const archive = await onlyArchive(dir);
      expect(await readdir(archive)).toContain('package.json');
      expect(
        fixed.findings.filter((f) => f.fixed && f.file).map((f) => `${f.checkId} ${f.file}`),
        'a fix landed, so this no longer isolates the archive half of the gate',
      ).toEqual([]);

      // ── The property ──
      expect(scansDuringFix, 'an archive holding a copy did not trigger the verify scan').toBe(2);

      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      expect(fixed.score).toBe(rescan.score);
      expect(fixed.rawScore).toBe(rescan.rawScore);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('treats an archive it cannot list as holding a copy', async () => {
    // A wrong "no" skips the scan that keeps the announced score honest; a
    // wrong "yes" costs one scan. Doubt has to land on "yes".
    const dir = tempDir('hma-381-unlisted-');
    try {
      const scanner = new HardeningScanner() as unknown as {
        backupContext?: { backupDir: string; targetDir: string; covered: Set<string> };
        ownArchiveHoldsCopies(): Promise<boolean>;
      };
      scanner.backupContext = {
        backupDir: path.join(dir, '.hackmyagent-backup', 'gone'),
        targetDir: dir,
        covered: new Set(),
      };
      expect(await scanner.ownArchiveHoldsCopies()).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
