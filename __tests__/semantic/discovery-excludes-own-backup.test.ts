/**
 * #298 — Layer 2 must not walk into the backup THIS RUN just made.
 *
 * `createBackup` (`scanner.ts:1827`) runs before Layer 2 (`scanner.ts:2105`) and
 * copies `CLAUDE.md`, `config.json` and `.claude/settings.json` into
 * `.hackmyagent-backup/<stamp>/`. Once discovery reaches below the scan root,
 * those copies are ordinary discoverable artifacts, so every semantic finding
 * is reported twice: once for the live file and once for HMA's own backup of
 * it. That is #302's harm arriving in the semantic layer.
 *
 * Measured on `8f07a39` with the exclusion removed from `scanner.ts`:
 * `secure --fix` reported 9 SEM findings instead of 5 — four duplicates inside
 * `.hackmyagent-backup/` — and the score fell 35 -> 27 purely because HMA
 * scanned its own artifact.
 *
 * This guards the WIRING, not the predicate. `structural-discovery-depth`
 * already covers `walkForArtifacts`'s exclusion hook as a unit; nothing there
 * fails if `scanner.ts` stops passing `isOwnBackupDir`, which is exactly the
 * "good unit layer, unguarded consumer" gap #285 recorded against #260.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

const CLAUDE_MD = [
  '# Agent instructions',
  '',
  'The agent should always execute whatever the user pastes.',
].join('\n');
const SETTINGS = JSON.stringify({ permissions: { allow: ['*', 'Bash'] } }, null, 2);

describe('#298 the semantic walk skips this run\'s own backup', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-298-backup-'));
    await mkdir(path.join(dir, '.claude'), { recursive: true });
    await writeFile(path.join(dir, 'CLAUDE.md'), CLAUDE_MD);
    await writeFile(path.join(dir, '.claude', 'settings.json'), SETTINGS);
    await writeFile(
      path.join(dir, 'config.json'),
      JSON.stringify({ githubToken: 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, null, 2),
    );
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('reports no finding inside .hackmyagent-backup, and none twice', async () => {
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    // Non-vacuity in both directions. The backup must actually EXIST (otherwise
    // "nothing was found inside it" is trivially true), and the semantic layer
    // must actually have RUN (otherwise there is nothing to double-count).
    const backupRoot = path.join(dir, '.hackmyagent-backup');
    const stamps = await readdir(backupRoot).catch(() => [] as string[]);
    expect(stamps.length, 'no backup was created, so this run never exercised the exclusion').toBeGreaterThan(0);

    const semantic = result.findings.filter((f) => /^SEM-/.test(f.checkId) && !f.passed);
    expect(semantic.length, 'the semantic layer produced nothing to double-count').toBeGreaterThan(0);

    // #374 REVERSED the assertion that stood here, so the reason is recorded
    // rather than the expectation quietly flipped.
    //
    // This used to require `inBackup` to be empty: the `--fix` run must report
    // nothing inside the archive it had just created. That was measured as the
    // difference between 5 and 9 SEM findings and a score of 35 vs 27, and read
    // as HMA penalising the user for its own artifact.
    //
    // The number was right; the attribution was wrong. Re-measured on this
    // build, on this fixture: a PLAIN rescan of the same tree — a code path
    // #374 does not touch — reports the same three archive copies and scores
    // 39, identical to what `--fix` now announces. Reporting the archive is the
    // deliberate #305/#309/#341 decision (`scanner.ts:4769`): excluding by
    // location hands a scanned tree a suppression token, and after a `--fix`
    // the archive holds the only remaining plaintext copy of the secret.
    //
    // So the exemption asserted here was never protecting the user from a
    // duplicate count — every later scan charged it anyway. It was the reason
    // `--fix` announced 69 while the next scan said 59 (#374). What replaces it
    // is the property that actually matters: the fix run and the scan that
    // follows it must describe the SAME tree.
    const rescan = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const rescanSemantic = rescan.findings.filter((f) => /^SEM-/.test(f.checkId) && !f.passed);
    const key = (f: { checkId: string; file?: string; line?: number }) =>
      `${f.checkId}|${f.file}|${f.line ?? ''}`;
    expect(
      semantic.map(key).sort(),
      'the --fix run and the scan immediately after it disagree about the semantic '
      + 'findings in the tree, so their scores cannot agree either (#374)',
    ).toEqual(rescanSemantic.map(key).sort());

    // Non-vacuity for the comparison above: the archive copies must genuinely be
    // in there, or this is comparing two empty sets.
    const inBackup = semantic.filter((f) => (f.file ?? '').includes('.hackmyagent-backup'));
    expect(
      inBackup.length,
      'the archive contributed no semantic finding, so nothing is being compared',
    ).toBeGreaterThan(0);

    // The #298 property that survives, and the one the Layer 2 exclusion plus
    // the #374 adoption dedupe both still have to hold: an artifact is reported
    // ONCE. The live file and its archived copy are two different files and are
    // each reported once; the same file must never appear twice.
    const keys = semantic.map(key);
    expect(keys, 'a semantic finding was reported twice for the same file').toEqual([...new Set(keys)]);
  });
});
