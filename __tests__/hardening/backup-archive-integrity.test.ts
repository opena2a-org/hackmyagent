/**
 * #314 — `--fix` must never rewrite a backup archive, and backups must not nest.
 *
 * Under #305 the archive exclusion required a LIVE counterpart, so a genuine
 * backup whose original had been moved or deleted stopped being recognised and
 * was scanned and rewritten:
 *
 *   secure --fix                     # <stamp1> holds the original token bytes
 *   mv config.json config.moved.json
 *   secure --fix                     # <stamp1>/config.json redacted to ${GITHUB_TOKEN}
 *
 * The original then survived only as
 * `.hackmyagent-backup/<stamp2>/.hackmyagent-backup/<stamp1>/config.json`, so
 * every run copied all previous archives into the new one and they grew
 * superlinearly.
 *
 * #305's justification was that the write hazard is "independently gated per
 * write by #300/#304". Those gate RECOVERABILITY — that a copy exists before a
 * write — not MUTATION, so they never stopped `--fix` from redacting the archive
 * the user restores from.
 *
 * No source change was needed for this: #309 closed both halves by replacing
 * the forgeable counterpart predicate with a write refusal keyed on the archive
 * itself, and by deleting `splitAtBackupDir`, which rebuilt real paths from a
 * `\`-folded string (the #304 defect one function away). These tests exist so
 * that stays true — the properties were verified, and nothing here guarded them.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

const ARCHIVE_STAMP = '2026-01-01-000000';

describe('#314 backup archives are never rewritten', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-314-'));
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /**
   * A prior run's archive whose original is GONE — the exact condition that
   * defeated the #305 counterpart test. No live `config.json` is written.
   */
  const seedOrphanedArchive = async (body: string): Promise<string> => {
    const archive = path.join(dir, '.hackmyagent-backup', ARCHIVE_STAMP);
    await mkdir(archive, { recursive: true });
    await writeFile(
      path.join(archive, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: ['config.json'],
        absentAtBackup: [],
        createdFiles: [],
      }),
    );
    const copy = path.join(archive, 'config.json');
    await writeFile(copy, body);
    return copy;
  };

  it('leaves an orphaned archive byte-identical after --fix', async () => {
    const body = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
    const archived = await seedOrphanedArchive(body);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    // Non-vacuity: the run must have SEEN the archived credential. If it did
    // not, "the bytes are unchanged" only says the walk never got there.
    expect(
      result.findings.some(
        (f) => f.checkId === 'CRED-001' && f.file?.includes('.hackmyagent-backup'),
      ),
      'the archived credential was never detected; this test is measuring nothing',
    ).toBe(true);

    expect(
      await readFile(archived, 'utf-8'),
      '--fix redacted the archive, so the original bytes rollback restores from are gone',
    ).toBe(body);
  });

  it('does not copy previous archives into the new one', async () => {
    await seedOrphanedArchive(JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
    // A real fixable finding, so this run genuinely creates its own backup.
    await writeFile(
      path.join(dir, 'settings.json'),
      JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
    );

    await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    const { readdir } = await import('node:fs/promises');
    const stamps = (await readdir(path.join(dir, '.hackmyagent-backup'))).filter(
      (s) => s !== ARCHIVE_STAMP,
    );
    expect(stamps.length, 'this run created no backup of its own').toBe(1);

    const nested = path.join(dir, '.hackmyagent-backup', stamps[0], '.hackmyagent-backup');
    let nestedExists = true;
    try {
      await readdir(nested);
    } catch {
      nestedExists = false;
    }
    expect(
      nestedExists,
      'the new backup contains a copy of the previous archive; backups nest and '
      + 'grow superlinearly with every run',
    ).toBe(false);
  });

  it('treats a backslash in a directory name as a filename byte, not a separator', async () => {
    // The `splitAtBackupDir` MEDIUM: it split on `[\\/]` and then rebuilt real
    // paths with `path.join`. On POSIX a backslash is a legal filename byte, so
    // a genuine archive under `we\ird` was described as `we/ird` and the two
    // stopped naming the same file — the #304 defect, one function away.
    //
    // Compared against a control whose name differs only in that byte: any
    // divergence at all is the defect, whatever produced it.
    const counts: Record<string, number> = {};
    for (const name of ['weird', 'we\\ird']) {
      const sub = await mkdtemp(path.join(tmpdir(), 'hma-314-bs-'));
      try {
        await writeFile(path.join(sub, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
        const archive = path.join(sub, name, '.hackmyagent-backup', ARCHIVE_STAMP);
        await mkdir(archive, { recursive: true });
        await writeFile(
          path.join(archive, '.manifest.json'),
          JSON.stringify({
            version: 2,
            existingFiles: ['config.json'],
            absentAtBackup: [],
            createdFiles: [],
          }),
        );
        const body = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
        await writeFile(path.join(archive, 'config.json'), body);
        await writeFile(path.join(sub, name, 'config.json'), body);

        const result = await new HardeningScanner().scan({ targetDir: sub, autoFix: false });
        counts[name] = result.findings.filter((f) => f.checkId === 'CRED-001').length;
      } finally {
        await rm(sub, { recursive: true, force: true });
      }
    }

    expect(counts['weird'], 'the control fixture did not fire; nothing is being compared')
      .toBeGreaterThan(0);
    expect(
      counts['we\\ird'],
      'a backslash in a directory name changed the finding count, so a real path is '
      + 'still being derived from a separator-folded description of it',
    ).toBe(counts['weird']);
  });
});
