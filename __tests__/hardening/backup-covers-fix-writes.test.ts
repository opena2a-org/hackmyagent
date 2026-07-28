/**
 * #300 — `secure --fix` must not rewrite a file the backup cannot restore.
 *
 * The backup candidate set was a static root-relative list (`BACKUP_FILES`)
 * predicted before the scan, while the set of files a fix WRITES is decided
 * during it. Every widening of detection therefore widened the write set
 * without widening the restorable set. #292 widened CRED-001 to config-shaped
 * files at any depth, and this shipped:
 *
 *   before   config/production.json + src/config.json  = a live token
 *   --fix    both -> ${GITHUB_TOKEN}
 *   backup   holds only package.json
 *   rollback "Restored 1 modified file", exit 0
 *   after    both still redacted — the original bytes are gone
 *
 * Irreversible data loss behind an explicit success message.
 *
 * The whole suite stayed green through it, because the existing backup tests
 * assert that a backup directory exists and that the ROOT candidates are in
 * it. Both remained true. So the assertion here is round-trip recovery of the
 * actual bytes — fix, then rollback, then compare against what was on disk
 * before — which is the property a user relies on and the only one that
 * fails when coverage lags detection.
 *
 * Credential values are synthesised at runtime from a repeated character,
 * never written as literals, so nothing here trips a secret scanner.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { BackupManifest } from '../../src/hardening/scanner';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'d'.repeat(36)}`;

async function withTree(
  files: Record<string, string>,
  body: (dir: string) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-300-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(path.join(dir, path.dirname(rel)), { recursive: true });
      await writeFile(path.join(dir, rel), content);
    }
    await body(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function readAll(dir: string, rels: string[]): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const rel of rels) out[rel] = await readFile(path.join(dir, rel), 'utf-8');
  return out;
}

async function latestManifest(dir: string): Promise<BackupManifest> {
  const base = path.join(dir, '.hackmyagent-backup');
  const { readdir } = await import('node:fs/promises');
  const stamps = (await readdir(base)).sort();
  const raw = await readFile(path.join(base, stamps[stamps.length - 1], '.manifest.json'), 'utf-8');
  return JSON.parse(raw) as BackupManifest;
}

const PKG = '{"name":"backup-fixture","version":"1.0.0"}\n';

describe('#300 every fix write is covered by the backup', () => {
  describe('credential fixes below the scan root', () => {
    // The exact placements #292 taught CRED-001 to reach. Each one was an
    // unrecoverable rewrite.
    const nested = {
      'package.json': PKG,
      'config/production.json': JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
      'src/config.json': JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n',
    };
    const targets = ['config/production.json', 'src/config.json'];

    it('restores the original bytes of a nested config after rollback', async () => {
      await withTree(nested, async (dir) => {
        const before = await readAll(dir, targets);

        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

        // Non-vacuity: if --fix did not actually rewrite these, the round
        // trip below is trivially satisfied and proves nothing.
        const afterFix = await readAll(dir, targets);
        for (const rel of targets) {
          expect(
            afterFix[rel],
            `--fix left ${rel} untouched; this test is measuring nothing`,
          ).not.toBe(before[rel]);
        }

        await new HardeningScanner().rollback(dir);

        const afterRollback = await readAll(dir, targets);
        for (const rel of targets) {
          expect(
            afterRollback[rel],
            `${rel} was rewritten by --fix and rollback could not restore it — `
            + 'the backup does not cover what the fix writes (#300)',
          ).toBe(before[rel]);
        }
      });
    });

    it('reports the restore honestly instead of claiming success over one file', async () => {
      await withTree(nested, async (dir) => {
        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
        const report = await new HardeningScanner().rollback(dir);
        for (const rel of targets) {
          expect(
            report.restored,
            `rollback reported success without naming ${rel}`,
          ).toContain(rel);
        }
      });
    });

    it('records the nested paths in the manifest, not just the root candidates', async () => {
      await withTree(nested, async (dir) => {
        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
        const manifest = await latestManifest(dir);
        for (const rel of targets) {
          expect(
            manifest.existingFiles,
            `${rel} was rewritten but never entered the manifest, so a rollback `
            + 'in a later process has nothing to restore from',
          ).toContain(rel);
        }
      });
    });
  });

  describe('gateway config fixes', () => {
    // `.openclaw/config.json` is a gateway fix target but was never a
    // BACKUP_FILES entry (the list has bare `openclaw.json`), and this write
    // site bypassed `applyFixWrite` entirely — the same defect reached by a
    // second code path, at the scan root rather than below it.
    const gateway = {
      'package.json': PKG,
      '.openclaw/config.json': JSON.stringify({ gateway: { host: '0.0.0.0', port: 8080 } }) + '\n',
    };

    it('restores the original bytes of a gateway config after rollback', async () => {
      await withTree(gateway, async (dir) => {
        const rel = '.openclaw/config.json';
        const before = await readAll(dir, [rel]);

        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

        const afterFix = await readAll(dir, [rel]);
        expect(
          afterFix[rel],
          'the gateway fix did not rewrite the config; this test is measuring nothing',
        ).not.toBe(before[rel]);

        await new HardeningScanner().rollback(dir);

        expect(
          (await readAll(dir, [rel]))[rel],
          'the gateway fix rewrote a config the backup does not cover (#300)',
        ).toBe(before[rel]);
      });
    });
  });

  describe('fail-safe direction', () => {
    it('abandons the write rather than writing what it cannot undo', async () => {
      await withTree({ 'package.json': PKG, 'config.json': '{"a":1}\n' }, async (dir) => {
        const scanner = new HardeningScanner();
        const target = path.join(dir, 'config.json');
        const before = await readFile(target, 'utf-8');

        // No backup context: this is the state after a `createBackup`
        // failure, which already downgrades the run to detect-only. A write
        // here would be unrevertable by construction.
        const landed = await (scanner as unknown as {
          applyFixWrite(f: string, c: string): Promise<boolean>;
        }).applyFixWrite(target, '{"a":2}\n');

        expect(landed, 'a fix wrote with no backup context behind it').toBe(false);
        expect(
          await readFile(target, 'utf-8'),
          'the file was rewritten even though nothing could restore it',
        ).toBe(before);
      });
    });

    it('does not let one run\'s backup authorise the next run\'s writes', async () => {
      await withTree({ 'package.json': PKG, 'config.json': '{"a":1}\n' }, async (dir) => {
        const scanner = new HardeningScanner();
        await scanner.scan({ targetDir: dir, autoFix: true });
        // Same instance, a detect-only run: the backup context from the
        // previous run must not survive into it.
        await scanner.scan({ targetDir: dir, autoFix: false });

        const target = path.join(dir, 'config.json');
        const before = await readFile(target, 'utf-8');
        const landed = await (scanner as unknown as {
          applyFixWrite(f: string, c: string): Promise<boolean>;
        }).applyFixWrite(target, '{"a":3}\n');

        expect(landed, 'a stale backup context authorised a write').toBe(false);
        expect(await readFile(target, 'utf-8')).toBe(before);
      });
    });
  });
});
