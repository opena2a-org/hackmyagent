/**
 * #338 — a rollback that cannot use the backup it selected must not be stuck
 * with it forever.
 *
 * Two mechanisms that are each defensible alone composed into a permanent denial
 * of the recovery path of a tool that had just rewritten the user's files:
 *
 *   - SELECTION is `readdir().sort().reverse()[0]` — the highest-sorting name,
 *     and the scanned tree writes the names. A cloned repo shipping
 *     `.hackmyagent-backup/9999-99-99-999999/` is selected every run.
 *   - RETENTION (#327) keeps the backup whenever anything went unrestored, so
 *     the run stopped consuming its own failure.
 *
 * Measured on the build this fixes, three runs on the same tree:
 *
 *   base 976e5b7   rollback 1 exit 0 (consumed the forged directory)
 *                  rollback 2 exit 0, "Restored 2 modified files", token back
 *   tip  cf26c5b   rollback 1..3 exit 1, all three selected 9999-99-99-999999,
 *                  original recovered: NO, both directories still on disk
 *
 * #327 traded silent data loss for unreachable data. Both halves are fixed
 * here and both are asserted: selection ADVANCES past a candidate it cannot read
 * at all, and retention is decided on whether the backup actually holds a copy
 * of something that did not go back rather than on the mere fact that something
 * did not.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

/** Sorts above every real stamp, and the scanned tree can write it. */
const FORGED = '9999-99-99-999999';

const exists = async (p: string): Promise<boolean> => {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
};

describe('#338 one unusable backup directory cannot wedge recovery', () => {
  let dir: string;
  let original: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-338-'));
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
    original = `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`;
    await writeFile(path.join(dir, 'config.json'), original);
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /** `--fix` for real, so the backup under test is one HackMyAgent made. */
  const fixForReal = async (): Promise<void> => {
    await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'the fix did not redact the credential; this test measures nothing',
    ).toContain('${GITHUB_TOKEN}');
  };

  /**
   * The reported wedge, end to end. The manifest names a file the directory does
   * not contain, which is the cheapest forgery there is: nothing to plant but a
   * name.
   */
  it('recovers the original bytes on the second rollback, not never', async () => {
    await fixForReal();
    const forged = path.join(dir, '.hackmyagent-backup', FORGED);
    await mkdir(forged, { recursive: true });
    await writeFile(
      path.join(forged, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: ['no-such-file.json'],
        absentAtBackup: [],
        createdFiles: [],
      }),
    );

    const first = await new HardeningScanner().rollback(dir);
    expect(first.unrestored.map((u) => u.path)).toContain('no-such-file.json');
    expect(
      first.backupRetainedAt,
      'a directory holding no copy of anything was kept, which is what wedges the next run',
    ).toBeUndefined();
    expect(await exists(forged), 'the unusable directory was kept on disk').toBe(false);

    const second = await new HardeningScanner().rollback(dir);
    expect(second.restored, 'the real backup was still not reached').toContain('config.json');
    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'the original bytes never came back',
    ).toBe(original);
  }, 120_000);

  /**
   * The other half. A candidate that cannot be read AT ALL used to throw, so no
   * rollback in that tree ever succeeded — retention had nothing to do with it,
   * and no number of runs helped. One run must reach past it.
   */
  it('advances past a candidate it cannot read and restores from the one behind it', async () => {
    await fixForReal();
    const unreadable = path.join(dir, '.hackmyagent-backup', FORGED);
    await mkdir(unreadable, { recursive: true });
    await writeFile(path.join(unreadable, '.manifest.json'), 'not json at all');

    const report = await new HardeningScanner().rollback(dir);

    expect(report.restored, 'the backup behind the unreadable one was not reached').toContain('config.json');
    expect(
      await readFile(path.join(dir, 'config.json'), 'utf-8'),
      'the original bytes were not recovered',
    ).toBe(original);
    expect(
      report.skippedBackups.map((s) => s.name),
      'the directory that was passed over is not reported',
    ).toContain(FORGED);
    expect(
      await exists(unreadable),
      'a directory HackMyAgent could not read was deleted anyway',
    ).toBe(true);
  }, 120_000);

  /**
   * CONTROL — #327's property must survive. A backup that DOES hold the only
   * copy of an entry that could not be restored is still kept, and the run still
   * reports itself incomplete.
   *
   * Correct on the previous build too. It is here so the retention condition
   * cannot be loosened into "delete whenever anything failed", which is the
   * data-loss direction #327 was filed over.
   */
  it('still keeps a backup that holds the only copy of an unrestored entry', async () => {
    const backup = path.join(dir, '.hackmyagent-backup', FORGED);
    await mkdir(path.join(backup, 'nested'), { recursive: true });
    await writeFile(path.join(backup, 'nested', 'kept.json'), 'THE ONLY COPY\n');
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: [path.join('nested', 'kept.json')],
        absentAtBackup: [],
        createdFiles: [],
      }),
    );
    // Unrestorable, with the copy genuinely in the backup: a directory stands
    // where the file has to be written.
    await mkdir(path.join(dir, 'nested', 'kept.json'), { recursive: true });

    const report = await new HardeningScanner().rollback(dir);

    expect(
      report.unrestored.map((u) => u.path),
      'the entry that could not be restored was not reported',
    ).toContain(path.join('nested', 'kept.json'));
    expect(report.backupRetainedAt, 'the only copy was deleted').toBeTruthy();
    expect(await readFile(path.join(backup, 'nested', 'kept.json'), 'utf-8')).toBe('THE ONLY COPY\n');
  });

  /**
   * The distinction the retention rule is made of, asserted directly: one entry
   * the backup really holds, one it never held, in a single manifest. Without
   * this, "keep when a copy is held" could be satisfied by a build that answers
   * `true` for everything — which is the previous behaviour under a new name.
   */
  it('separates an entry the backup holds from one it never held', async () => {
    const backup = path.join(dir, '.hackmyagent-backup', FORGED);
    await mkdir(path.join(backup, 'nested'), { recursive: true });
    await writeFile(path.join(backup, 'nested', 'kept.json'), 'THE ONLY COPY\n');
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: [path.join('nested', 'kept.json'), 'never-existed.json'],
        absentAtBackup: [],
        createdFiles: [],
      }),
    );
    await mkdir(path.join(dir, 'nested', 'kept.json'), { recursive: true });

    const report = await new HardeningScanner().rollback(dir);

    expect(
      report.unrestored.filter((u) => u.backupHoldsCopy).map((u) => u.path),
      'the entry the backup really holds was not marked as held',
    ).toEqual([path.join('nested', 'kept.json')]);
    expect(
      report.unrestored.filter((u) => !u.backupHoldsCopy).map((u) => u.path),
      'an entry the backup never held was reported as held',
    ).toEqual(['never-existed.json']);
  });

  /**
   * #347.4 — the reason has to be about the cause that actually applied. One
   * sentence used to be printed for a `..`, for a dangling link and for an
   * EACCES, and it named a traversal in all three.
   */
  it('gives each refusal its own reason', async () => {
    const backup = path.join(dir, '.hackmyagent-backup', FORGED);
    await mkdir(backup, { recursive: true });
    await writeFile(
      path.join(backup, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: ['../escapes.json', 'absent.json'],
        absentAtBackup: [],
        createdFiles: [],
      }),
    );

    const report = await new HardeningScanner().rollback(dir);
    const reasons = new Map(report.unrestored.map((u) => [u.path, u.reason]));

    expect(reasons.get('../escapes.json')).toBe(
      'the manifest entry points outside the scanned directory',
    );
    expect(reasons.get('absent.json')).toBe('the backup holds no readable copy of it');
    expect(
      new Set(reasons.values()).size,
      'two different causes were given the same sentence',
    ).toBe(2);
  });
});
