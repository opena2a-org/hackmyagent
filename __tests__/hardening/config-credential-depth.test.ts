/**
 * #292 — credential detection for config-shaped files was root-only.
 *
 * The same GitHub token scored 69/100 with CRED-001 at `./config.json` and
 * 96/100 with NO credential finding at `src/config.json`, `sub/config.json` or
 * `config/production.json`, because `checkCredentialExposure` probed a fixed
 * list of `path.join(targetDir, name)` paths. A conventional layout therefore
 * passed clean. Code files were never affected — the AST layer covers those at
 * any depth (AST-CRED-001/003) — so the gap was specific to config-shaped
 * files below the scan root.
 *
 * These tests run the scanner in-process (no spawn) so they are fast and can
 * be mutation-checked cheaply. Credential values are synthesised at runtime
 * from a repeated character, never written as literals, so nothing here trips
 * GitHub push protection or a secret scanner.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

async function scanTreeWithConfigAt(relPath: string) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-292-'));
  try {
    await mkdir(path.join(dir, path.dirname(relPath)), { recursive: true });
    await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
    await writeFile(path.join(dir, relPath), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: dir, autoFix: false });
    const cred = result.findings.filter(
      (f) => f.checkId === 'CRED-001' && !f.passed
    );
    return { result, cred };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('#292 config-shaped credential detection below the scan root', () => {
  // Each of these was a silent 96/100 "no credential finding" before the fix.
  const nestedPlacements = [
    'sub/config.json',
    'src/config.json',
    'deep/a/b/settings.json',
    'config/production.json', // config-shaped by LOCATION, not by filename
    'conf/db.yaml',
  ];

  for (const rel of nestedPlacements) {
    it(`detects a credential at ${rel}`, async () => {
      const { cred } = await scanTreeWithConfigAt(rel);
      expect(
        cred.length,
        `no CRED-001 for a token at ${rel} — the root-only probe regressed`
      ).toBeGreaterThan(0);
    });

    it(`names ${rel} as the finding location, not just the basename`, async () => {
      const { cred } = await scanTreeWithConfigAt(rel);
      // A finding that cannot say WHERE the credential is fails CISO Rule 11.
      expect(cred.map((f) => f.file)).toContain(rel);
    });
  }

  it('still detects a credential at the scan root (no coverage lost)', async () => {
    const { cred } = await scanTreeWithConfigAt('config.json');
    expect(cred.length).toBeGreaterThan(0);
    expect(cred.map((f) => f.file)).toContain('config.json');
  });

  it('scores a nested credential the same as a root one', async () => {
    const root = await scanTreeWithConfigAt('config.json');
    const nested = await scanTreeWithConfigAt('src/config.json');
    // The whole point of #292: placement must not change the verdict.
    expect(nested.result.score).toBe(root.result.score);
  });

  it('does not fire on a non-config file inside a config directory', async () => {
    // `config/README.md` sits in a config dir but is not structured config.
    // Guards the location rule from becoming "anything under config/".
    const { cred } = await scanTreeWithConfigAt('config/README.md');
    expect(cred.map((f) => f.file)).not.toContain('config/README.md');
  });

  it('never treats HMA\'s own backup directory as a scan target', async () => {
    // The recursive walk descends into everything except .git/node_modules, and
    // `.hackmyagent-backup/` holds verbatim copies of the files this very check
    // rewrites. Without an explicit exclusion, `--fix` substituted the
    // credential INSIDE the backup, so `rollback` restored already-redacted
    // content and the original was gone — the backup silently stopped being a
    // backup. It also double-counted every finding.
    const dir = await mkdtemp(path.join(tmpdir(), 'hma-292-bak-'));
    try {
      await writeFile(path.join(dir, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
      await mkdir(path.join(dir, '.hackmyagent-backup', '2026-01-01T00-00-00'), { recursive: true });
      const backupCopy = path.join(dir, '.hackmyagent-backup', '2026-01-01T00-00-00', 'config.json');
      const backupBody = JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n';
      await writeFile(backupCopy, backupBody);

      const scanner = new HardeningScanner();
      const result = await scanner.scan({ targetDir: dir, autoFix: true });

      const backupFindings = result.findings.filter((f) => f.file?.includes('.hackmyagent-backup'));
      expect(backupFindings, 'the backup directory must not produce findings').toEqual([]);

      const { readFile } = await import('node:fs/promises');
      expect(
        await readFile(backupCopy, 'utf-8'),
        '--fix rewrote the backup copy; rollback would restore redacted content'
      ).toBe(backupBody);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('treats a nested .env as an env file, not a rewritable config file', async () => {
    // `isEnvFile` keys on basename; a raw `startsWith` on the relative path
    // would classify `sub/.env` as ordinary config and mark it auto-fixable,
    // which means --fix would rewrite the file whose whole purpose is to hold
    // the real value.
    const { cred } = await scanTreeWithConfigAt('sub/.env');
    const envFinding = cred.find((f) => f.file === 'sub/.env');
    expect(envFinding, 'no CRED-001 raised for a nested .env').toBeDefined();
    expect(envFinding?.fixable, 'a nested .env must not be auto-fixable').toBe(false);
  });
});
