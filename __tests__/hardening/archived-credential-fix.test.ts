/**
 * #384 — a credential finding inside a backup archive must carry the archive
 * remediation whichever detector produced it.
 *
 * After #374 a `secure --fix` run adopts the findings its verify scan reports
 * inside the archive it just created. CRED-001 on an archived `config.json`
 * already said "Rotate the credential, then remove this plaintext copy by
 * hand"; the Layer-2 detector on the SAME file (SEM-CRED-*) said
 * `opena2a protect <target>`, which migrates the live tree and cannot move an
 * archive copy. The summary then offered `Protect credentials:` and counted the
 * copies under "Run `fix-all`", both dead ends for those findings.
 *
 * Only the advice changes. Check, severity and score stay the detector's.
 *
 * #376 — `--fix` keeps its copies in the backup store, outside the tree, so a
 * run no longer has archived findings of its own to adopt. The archive these
 * cells measure is the one 0.25.x to 0.33.x wrote into the tree: it stays
 * scanned and reported until the user deletes it, and its copies still need the
 * archive remediation whichever detector reports them and whether or not the
 * run fixes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { latestStoreRun } from '../helpers/backup-store';
import { tempDir } from '../helpers/temp-dir';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;
const ARCHIVE_FIX = 'Rotate the credential, then remove this plaintext copy by hand';
const LIVE_TREE_FIX = /\bopena2a\s+protect\b|\bsecure\b[^\n]*--fix/;

const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');

function inArchive(f: SecurityFinding): boolean {
  return (f.file ?? '').split(/[\\/]/).includes('.hackmyagent-backup');
}

function isCredential(f: SecurityFinding): boolean {
  return f.checkId.startsWith('CRED-') || f.checkId.startsWith('SEM-CRED-');
}

/** The issue's fixture: credentials `--fix` redacts, so its archive keeps the plaintext. */
async function makeFixture(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
  await writeFile(path.join(dir, '.gitignore'), 'node_modules/\n');
  await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
  return dir;
}

/** The layout earlier versions wrote: `<target>/.hackmyagent-backup/<stamp>/`, holding the pre-fix copy. */
const LEGACY_STAMP = '2026-01-01-000000000-000-00000000';
async function seedEarlierArchive(dir: string): Promise<string> {
  const stamp = path.join(dir, '.hackmyagent-backup', LEGACY_STAMP);
  await mkdir(stamp, { recursive: true });
  await writeFile(path.join(stamp, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
  return stamp;
}

describe('#384 archived credential findings carry the archive remediation', () => {
  it('a --fix run gives every archived credential finding the archive fix, not a live-tree command', async () => {
    const dir = await makeFixture('hma-384-fix-');
    try {
      const stamp = await seedEarlierArchive(dir);
      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const archived = result.findings.filter((f) => !f.passed && !f.fixed && inArchive(f) && isCredential(f));

      // Load-bearing: the Layer-2 detector must be among them, or this test
      // only re-checks what CRED-001 already did before the change.
      expect(archived.some((f) => f.checkId.startsWith('SEM-CRED-'))).toBe(true);
      expect(archived.some((f) => f.checkId === 'CRED-001')).toBe(true);

      for (const f of archived) {
        expect(f.fix, `${f.checkId} ${f.file}`).toBe(ARCHIVE_FIX);
        expect(f.fix ?? '').not.toMatch(LIVE_TREE_FIX);
        expect(f.fixable, `${f.checkId} ${f.file}`).toBe(false);
        expect(f.guidance ?? '').toContain('.hackmyagent-backup');
        expect(f.inArchive, `${f.checkId} ${f.file}`).toBe(true);
        // #376 — every archived finding is in the earlier version's archive.
        // This run's own copy is in the store and produces none.
        expect(f.file, `${f.checkId} is attributed to a backup this run wrote into the tree`).toContain(LEGACY_STAMP);
      }

      // The run did fix the live file and did archive it, outside the tree.
      expect(await readFile(path.join(dir, 'config.json'), 'utf-8')).not.toContain(FAKE_GH_TOKEN);
      expect(await readFile(path.join(await latestStoreRun(dir), 'config.json'), 'utf-8')).toContain(FAKE_GH_TOKEN);
      expect(await readdir(path.join(dir, '.hackmyagent-backup')), '--fix wrote a backup into the tree').toEqual([LEGACY_STAMP]);
      // And never edited the earlier copy: rollback from it restores these bytes.
      expect(await readFile(path.join(stamp, 'config.json'), 'utf-8')).toContain(FAKE_GH_TOKEN);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('a plain scan of a tree holding an archive treats its copies the same way, and leaves live files alone', async () => {
    const dir = await makeFixture('hma-384-rescan-');
    try {
      await seedEarlierArchive(dir);

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const failing = result.findings.filter((f) => !f.passed && isCredential(f));

      const archivedSem = failing.filter((f) => inArchive(f) && f.checkId.startsWith('SEM-CRED-'));
      const liveSem = failing.filter((f) => !inArchive(f) && f.checkId.startsWith('SEM-CRED-'));
      expect(archivedSem.length).toBeGreaterThan(0);
      expect(liveSem.length).toBeGreaterThan(0);

      for (const f of archivedSem) expect(f.fix, `${f.checkId} ${f.file}`).toBe(ARCHIVE_FIX);
      // Negative control: the live copy keeps the detector's own remediation.
      for (const f of liveSem) expect(f.fix, `${f.checkId} ${f.file}`).not.toBe(ARCHIVE_FIX);

      // Advice only: an archived copy keeps the severity its live twin has.
      for (const a of archivedSem) {
        const twin = liveSem.find((l) => l.checkId === a.checkId);
        if (twin) expect(a.severity).toBe(twin.severity);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe.skipIf(process.platform === 'win32' || !existsSync(CLI))('#384 secure --fix report offers no live-tree step for archive copies', () => {
  beforeAll(assertDistFreshIfPresent);

  const secureFix = (dir: string, home: string): string => {
    const res = spawnSync(process.execPath, [CLI, 'secure', dir, '--fix'], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, HOME: home, OPENA2A_HOME: home, NO_COLOR: '1' },
    });
    // eslint-disable-next-line no-control-regex
    return (res.stdout ?? '').replace(/\x1b\[[0-9;]*m/g, '');
  };

  it('prints the archive fix and no Protect credentials step for copies in an earlier backup', async () => {
    const dir = await makeFixture('hma-384-cli-');
    const home = await mkdtemp(path.join(tmpdir(), 'hma-384-home-'));
    try {
      await seedEarlierArchive(dir);
      const out = secureFix(dir, home);

      // The run did produce archive-located findings, so the checks below bite.
      expect(out).toContain(`.hackmyagent-backup/${LEGACY_STAMP}/config.json`);
      expect(out).toContain(`Fix: ${ARCHIVE_FIX}`);
      expect(out).not.toMatch(/Fix: npx opena2a-cli protect/);
      expect(out).not.toMatch(/Protect credentials:/);
    } finally {
      await rm(dir, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
    }
  });

  it('reports no archive copy, no Protect credentials step and nothing left for fix-all when the only copy is its own', async () => {
    // The case the three assertions were written for: the only plaintext left
    // after `--fix` is the copy the run archived. #376 — that copy is in the
    // store, so it is no finding at all, and none of the live-tree steps that
    // could not have moved it is offered.
    const dir = await makeFixture('hma-384-cli-');
    const home = tempDir('hma-384-home-');
    try {
      const out = secureFix(dir, home);

      // The run did archive the plaintext, so "no copy reported" is a measurement.
      expect(out).toContain('Backup created:');
      expect(await readFile(path.join(await latestStoreRun(dir), 'config.json'), 'utf-8')).toContain(FAKE_GH_TOKEN);
      expect(existsSync(path.join(dir, '.hackmyagent-backup'))).toBe(false);

      expect(out).not.toContain('.hackmyagent-backup');
      expect(out).not.toContain(`Fix: ${ARCHIVE_FIX}`);
      expect(out).not.toMatch(/Fix: npx opena2a-cli protect/);
      expect(out).not.toMatch(/Protect credentials:/);
      expect(out).not.toMatch(/remaining issues? ha(?:s|ve) fix guidance/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
