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

/**
 * #326 — no citation asserts WHO created a `.hackmyagent-backup`-named
 * directory, and none offers to delete one.
 *
 * #319 gated the claim on the archive's manifest LISTING the cited file, and
 * #323 was supposed to be the lesson about fixture strength. The test written
 * for it used `existingFiles: []` — the weakest forgery in the input space — so
 * it passed while ONE array element restored the full `rm -rf` citation against
 * a directory holding somebody else's source. The manifest is a file in the
 * scanned tree; the tree chooses its location and its contents.
 *
 * These fixtures therefore use the STRONGEST forgery available to the tree (a
 * manifest that names exactly the file HMA is reporting), plus the base-directory
 * escalation, plus a genuine archive — and they assert the emitted `fix`,
 * `guidance` and `description`, not the finding count.
 */
describe('#326 archive citations claim no provenance and delete nothing', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-319-'));
    await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  });

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /** The measured fixture: unrelated source under an attacker-chosen name. */
  const seedNamedButNotOurs = async (manifest?: string): Promise<string> => {
    const archive = path.join(dir, 'vendor', '.hackmyagent-backup', 'important-lib');
    await mkdir(path.join(archive, 'config'), { recursive: true });
    await writeFile(path.join(archive, 'main.js'), 'module.exports = () => 1;\n');
    if (manifest !== undefined) await writeFile(path.join(archive, '.manifest.json'), manifest);
    const holder = path.join(archive, 'config', 'production.json');
    await writeFile(holder, JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
    return holder;
  };

  const credFinding = (findings: readonly { checkId: string; file?: string }[]) =>
    findings.find((f) => f.checkId === 'CRED-001' && f.file?.includes('production.json'));

  /**
   * The forgery the #319 test should have used: a manifest that names EXACTLY the
   * file being reported. Nothing about it is harder to write than the empty one —
   * it is the same file with one string in one array — and it is what restored
   * the citation in full.
   */
  it('offers no rm -rf when the manifest names the very file being reported', async () => {
    await seedNamedButNotOurs(
      JSON.stringify({
        version: 2,
        // The strongest claim the tree can make about itself.
        existingFiles: ['config/production.json'],
        absentAtBackup: [],
        createdFiles: [],
      }),
    );

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const finding = credFinding(result.findings);

    // Non-vacuity: the credential must be REPORTED. Silence would satisfy every
    // assertion below while being a worse outcome than the defect.
    expect(finding, 'the credential inside the named directory was not reported at all')
      .toBeDefined();
    expect(
      finding!.fix,
      'a manifest listing the file bought a recursive deletion of somebody else\'s source',
    ).not.toContain('rm -rf');
    expect(finding!.guidance ?? '', 'HMA asserted it created a directory it did not create')
      .not.toContain('copy `--fix` saved');
    expect(finding!.description, 'the description claims the file is a HackMyAgent backup')
      .not.toContain('HackMyAgent backup');
    // Still not a dead end: the finding says what to do, and names the check
    // that tells the user which case they are in.
    expect(finding!.fix, 'the finding has no path forward at all').toBeTruthy();
    expect(finding!.guidance ?? '', 'no verify step for deciding whether this is a backup')
      .toContain('secure');
  });

  /**
   * The escalation, at identical attacker cost. A credential sitting DIRECTLY in
   * the base makes the base itself the archive directory, so the emitted
   * deletion covered every real prior-run backup stored beside it.
   */
  it('offers no rm -rf aimed at the whole backup base, where real backups live', async () => {
    const base = path.join(dir, '.hackmyagent-backup');
    const realPriorRun = path.join(base, ARCHIVE_STAMP);
    await mkdir(realPriorRun, { recursive: true });
    await writeFile(path.join(realPriorRun, 'config.json'), '{"real":"prior backup copy"}\n');
    await writeFile(
      path.join(base, '.manifest.json'),
      JSON.stringify({
        version: 2,
        existingFiles: ['config.json'],
        absentAtBackup: [],
        createdFiles: [],
      }),
    );
    const holder = path.join(base, 'config.json');
    await writeFile(holder, JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const finding = result.findings.find(
      (f) => f.checkId === 'CRED-001' && f.file?.endsWith(path.join('.hackmyagent-backup', 'config.json')),
    );

    expect(finding, 'the credential in the backup base was not reported').toBeDefined();
    expect(
      finding!.fix,
      'a deletion was offered for the base directory, which holds every prior backup',
    ).not.toContain('rm -rf');
    // The real prior-run copy is still there: no emitted command targets it.
    expect(await readFile(path.join(realPriorRun, 'config.json'), 'utf-8'))
      .toBe('{"real":"prior backup copy"}\n');
  });

  /**
   * A manifest that does not parse establishes nothing either — kept as its own
   * case because "the file could not be read" is a different code path from "the
   * file said no".
   */
  it('offers no rm -rf for a manifest that does not parse', async () => {
    await seedNamedButNotOurs('{ this is not json');

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const finding = credFinding(result.findings);

    expect(finding, 'the credential was not reported').toBeDefined();
    expect(finding!.fix, 'an unparseable manifest bought provenance').not.toContain('rm -rf');
  });

  /**
   * A GENUINE archive gets the same treatment: reported, not auto-edited, no
   * deletion offered, and no sentence claiming HMA wrote it. HMA cannot tell
   * this fixture apart from the forgery above — that is the whole finding — so
   * the honest output is the same for both.
   */
  it('claims nothing and deletes nothing for a real archive either', async () => {
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
    await writeFile(
      path.join(archive, 'config.json'),
      JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
    );

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const finding = result.findings.find(
      (f) => f.checkId === 'CRED-001' && f.file?.includes(ARCHIVE_STAMP),
    );

    expect(finding, 'the archived credential was not reported').toBeDefined();
    expect(finding!.fix, 'a destructive citation is still emitted for an archive')
      .not.toContain('rm -rf');
    expect(finding!.guidance ?? '', 'HMA still asserts it created this directory')
      .not.toContain('copy `--fix` saved');
    expect(finding!.fixable, 'an archive was offered to `secure --fix`').toBe(false);
  });

  /**
   * The control that keeps every `not.toContain('rm -rf')` above honest: an
   * ordinary credential OUTSIDE any archive still reports, is still fixable, and
   * still gets `secure --fix`. Without this, a build that dropped CRED-001
   * altogether would pass this whole describe block.
   */
  it('still reports and offers secure --fix for an ordinary credential (the control)', async () => {
    await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const finding = result.findings.find(
      (f) => f.checkId === 'CRED-001' && f.file === 'config.json',
    );

    expect(finding, 'an ordinary plaintext credential was not reported').toBeDefined();
    expect(finding!.fixable, 'an ordinary credential is no longer fixable').toBe(true);
    expect(finding!.fix).toContain('secure --fix');
  });

  /**
   * #323 — the fixtures in this file were all case-exact. Recognition of an
   * archive by NAME governs the write refusal, and on a case-insensitive
   * filesystem `.HACKMYAGENT-BACKUP` is the same directory (#317). Folding case
   * can only refuse MORE writes, so this holds on a case-sensitive filesystem
   * too: the name is matched, the archive is not rewritten.
   */
  it('refuses to rewrite an archive whose name differs only in case', async () => {
    const archive = path.join(dir, '.HACKMYAGENT-BACKUP', ARCHIVE_STAMP);
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
    const copy = path.join(archive, 'config.json');
    await writeFile(copy, body);
    // A live fixable finding, so the run really does take a backup and run fixes.
    await writeFile(path.join(dir, 'settings.json'), body);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(
      result.findings.some((f) => f.checkId === 'CRED-001' && f.file?.includes(ARCHIVE_STAMP)),
      'the archived credential was never detected; this test is measuring nothing',
    ).toBe(true);
    expect(
      await readFile(copy, 'utf-8'),
      'the archive was rewritten through a case variant of its name',
    ).toBe(body);
  });
});
