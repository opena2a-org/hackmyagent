/**
 * #381 / #376 — the post-fix verify scan runs when there is a fix to verify,
 * and only then.
 *
 * #374 made `secure --fix` run a second, context-free scan whenever its archive
 * held a copy, because the archive sat inside the scanned tree and only such a
 * scan could say what the next scan would score with it. #381 found that gate
 * read `backupContext.covered.size`, which is above zero on an empty directory,
 * so every `--fix` paid for two full scans.
 *
 * #376 moved the archive out of the tree, into the per-user backup store, and
 * the archive half of the gate went with it: a copy in the store cannot move any
 * scan's result. What remains is the scan's first job, confirming the fixes
 * that landed.
 *
 * All three directions are pinned:
 *   1. nothing fixed, nothing copied: one scan;
 *   2. nothing fixed, a copy in the store: still one scan, and the announced
 *      score is the rescan's (the case #374 needed the second scan for). Since
 *      #1039 a copy is taken only for a fix write, so this is a write refused
 *      after its copy;
 *   3. a fix landed: the verify scan runs.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdir, writeFile, rm, readdir, readFile, symlink } from 'node:fs/promises';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { fs as trackedFs } from '../../src/hardening/tracked-fs';
import { tempDir } from '../helpers/temp-dir';
import { latestStoreRun, storeRuns } from '../helpers/backup-store';

async function onlyArchive(dir: string): Promise<string> {
  expect((await storeRuns(dir)).length, 'no archive was created, so this run exercised nothing').toBe(1);
  return latestStoreRun(dir);
}

const GITIGNORE = '.env\n.env.*\nsecrets.json\ncredentials.json\n*.pem\n*.key\n.idea/\n.vscode/\nnode_modules/\ndist/\n';

describe('#381/#376 the post-fix verify scan runs only when a fix landed', () => {
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
      await writeFile(path.join(root, 'shared', '.gitignore'), GITIGNORE);
      await symlink(path.join('..', 'shared', '.gitignore'), path.join(dir, '.gitignore'));

      const scan = vi.spyOn(HardeningScanner.prototype, 'scan');
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const scansDuringFix = scan.mock.calls.length;
      vi.restoreAllMocks();

      // ── Non-vacuity ──
      // The archive exists and holds no copy, and the manifest lists absent
      // candidates — the entries that made the #381 gate true.
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
      expect(scansDuringFix, 'a run with nothing to verify triggered a second full scan (#381)').toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('skips the second scan when the archive holds a copy and nothing was fixed', async () => {
    const dir = tempDir('hma-381-copy-');
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      // Missing the credential entries, so a .gitignore fix computes a rewrite.
      await writeFile(path.join(dir, '.gitignore'), 'node_modules/\ndist/\n');
      await mkdir(path.join(dir, 'src'), { recursive: true });
      await writeFile(path.join(dir, 'src', 'index.js'), 'module.exports = 1;\n');

      // #1039 — a run copies a file only when a fix is about to write it, so a
      // copy with nothing fixed is a write refused after the copy was taken.
      // The refusal is the filesystem's, on the target's .gitignore alone.
      const target = trackedFs as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
      const writeFileReal = target.writeFile;
      vi.spyOn(target, 'writeFile').mockImplementation(async (...args: unknown[]) => {
        if (typeof args[0] === 'string' && path.basename(args[0]) === '.gitignore') {
          const err = new Error(`EPERM: operation not permitted, open '${args[0]}'`) as NodeJS.ErrnoException;
          err.code = 'EPERM';
          throw err;
        }
        return writeFileReal(...args);
      });
      const scan = vi.spyOn(HardeningScanner.prototype, 'scan');
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const scansDuringFix = scan.mock.calls.length;
      vi.restoreAllMocks();

      // ── Non-vacuity ──
      // A copy landed in the archive and no fix landed: before #376 this was the
      // one case that ran the second scan for the archive's sake alone.
      const archive = await onlyArchive(dir);
      expect(await readdir(archive)).toContain('.gitignore');
      expect(
        fixed.findings.filter((f) => f.checkId === 'FIX-WRITE-FAILED').map((f) => f.file),
        'the .gitignore write was not attempted and refused, so the copy is not one a fix took',
      ).toEqual(['.gitignore']);
      expect(
        fixed.findings.filter((f) => f.fixed && f.file).map((f) => `${f.checkId} ${f.file}`),
        'a fix landed, so this no longer isolates the archive half of the gate',
      ).toEqual([]);

      // ── The property ──
      expect(scansDuringFix, 'a copy in the backup store triggered a second full scan').toBe(1);

      // The copy in the store moves no result: apart from the finding that
      // reports this run's refused write, which only a `--fix` run can carry,
      // the run's findings are the rescan's.
      const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const key = (f: { checkId: string; file?: string; passed: boolean; severity: string }): string =>
        `${f.checkId}|${f.file ?? ''}|${f.passed}|${f.severity}`;
      expect(
        fixed.findings.filter((f) => f.checkId !== 'FIX-WRITE-FAILED').map(key).sort(),
      ).toEqual(rescan.findings.map(key).sort());
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('runs the second scan when a fix landed, to confirm it', async () => {
    // An empty tree: GIT-001 writes a `.gitignore`, which is the fix to verify.
    const dir = tempDir('hma-381-fixed-');
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');

      const scan = vi.spyOn(HardeningScanner.prototype, 'scan');
      const fixed = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const scansDuringFix = scan.mock.calls.length;
      vi.restoreAllMocks();

      const landed = fixed.findings.filter((f) => f.fixed && f.file);
      expect(landed.length, 'no fix landed, so there was nothing to verify').toBeGreaterThan(0);
      expect(scansDuringFix, 'a fix that landed was not verified').toBe(2);
      expect(landed.every((f) => f.fixVerified !== undefined), 'a landed fix carries no verification result').toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
