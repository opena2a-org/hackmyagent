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
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

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

describe('#384 archived credential findings carry the archive remediation', () => {
  it('a --fix run gives every archived credential finding the archive fix, not a live-tree command', async () => {
    const dir = await makeFixture('hma-384-fix-');
    try {
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
        expect(f.inOwnArchive).toBe(true);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('a plain scan of a tree holding an archive treats its copies the same way, and leaves live files alone', async () => {
    const dir = await makeFixture('hma-384-rescan-');
    try {
      const stamp = path.join(dir, '.hackmyagent-backup', '2026-01-01-000000000-000-00000000');
      await mkdir(stamp, { recursive: true });
      await writeFile(path.join(stamp, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

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

  it('prints the archive fix, no Protect credentials step, and does not count copies toward fix-all', async () => {
    const dir = await makeFixture('hma-384-cli-');
    const home = await mkdtemp(path.join(tmpdir(), 'hma-384-home-'));
    try {
      const res = spawnSync(process.execPath, [CLI, 'secure', dir, '--fix'], {
        encoding: 'utf8',
        timeout: 120_000,
        env: { ...process.env, HOME: home, OPENA2A_HOME: home, NO_COLOR: '1' },
      });
      // eslint-disable-next-line no-control-regex
      const out = (res.stdout ?? '').replace(/\x1b\[[0-9;]*m/g, '');

      // The run did produce archive-located findings, so the checks below bite.
      expect(out).toMatch(/inside the backup this run created/);
      expect(out).toContain(`Fix: ${ARCHIVE_FIX}`);
      expect(out).not.toMatch(/Fix: npx opena2a-cli protect/);
      expect(out).not.toMatch(/Protect credentials:/);
      expect(out).not.toMatch(/remaining issues? ha(?:s|ve) fix guidance/);
    } finally {
      await rm(dir, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
    }
  });
});
