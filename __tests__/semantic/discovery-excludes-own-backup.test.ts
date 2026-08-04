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

    const inBackup = semantic.filter((f) => (f.file ?? '').includes('.hackmyagent-backup'));
    expect(
      inBackup.map((f) => `${f.checkId} ${f.file}`),
      'HMA reported findings against its own backup copies',
    ).toEqual([]);

    // The duplication is the user-visible harm: the same checkId against the
    // same artifact, once live and once backed up.
    const keys = semantic.map((f) => `${f.checkId}|${f.file}|${f.line ?? ''}`);
    expect(keys, 'a semantic finding was reported twice').toEqual([...new Set(keys)]);
  });
});
