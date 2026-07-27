// Regression gate: a symlinked backup candidate must never be followed.
//
// `createBackup` used `fs.access` + `fs.copyFile`, both of which follow
// symlinks. A repo shipping `SOUL.md -> ~/.ssh/id_rsa` therefore had that
// key's bytes copied into `<repo>/.hackmyagent-backup/<ts>/SOUL.md` — an
// out-of-tree secret pulled inside the scanned tree, where it can then be
// committed, archived, or read by other tooling. The write side is worse:
// the governance auto-fix appends generated sections through the link and
// mutates the target file.
//
// `findSkillFiles` and the web-directory walk already skip symlinks;
// `BACKUP_FILES` did not — and adding `SOUL.md` to that list for #262 is
// what put a governance file (the thing harden-soul writes) on the
// followed path.
//
// Contract: a symlinked candidate is skipped entirely — not backed up, and
// not recorded in `absentAtBackup` either, since listing it there would let
// `recordCreatedFiles` later treat it as something HMA generated.

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

const created: string[] = [];

function makeTree(): { root: string; repo: string; secret: string } {
  const root = mkdtempSync(join(tmpdir(), 'hma-symlink-'));
  created.push(root);
  const repo = join(root, 'repo');
  mkdirSync(repo);
  const secret = join(root, 'secret-target.txt');
  writeFileSync(secret, 'PRIVATE KEY MATERIAL - must never be copied or appended to\n');
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 's', version: '1.0.0' }));
  return { root, repo, secret };
}

afterEach(() => {
  while (created.length) rmSync(created.pop()!, { recursive: true, force: true });
});

function backupDirOf(repo: string): string | undefined {
  const base = join(repo, '.hackmyagent-backup');
  if (!existsSync(base)) return undefined;
  const entries = readdirSync(base);
  return entries.length ? join(base, entries[0]) : undefined;
}

describe('createBackup does not follow symlinked candidates', () => {
  it('never copies the target of a symlinked SOUL.md into the backup', async () => {
    const { repo, secret } = makeTree();
    symlinkSync(secret, join(repo, 'SOUL.md'));

    const scanner = new HardeningScanner();
    const backupDir = await (scanner as any).createBackup(repo);

    // Non-vacuity: the backup must actually have run and captured the
    // ordinary, non-symlinked candidate. Otherwise "no SOUL.md in the
    // backup" would be true for the wrong reason.
    expect(backupDir, 'createBackup produced no directory').toBeTruthy();
    const manifest = JSON.parse(
      readFileSync(join(backupDir as string, '.manifest.json'), 'utf-8'),
    );
    expect(manifest.existingFiles, 'the real file was not backed up').toContain('package.json');

    // The actual contract.
    expect(existsSync(join(backupDir as string, 'SOUL.md')), 'symlink target was copied into the backup').toBe(false);
    expect(manifest.existingFiles).not.toContain('SOUL.md');
    // Not recorded as absent either — it exists, it is simply not ours to
    // manage. Recording it would let recordCreatedFiles() adopt it.
    expect(manifest.absentAtBackup).not.toContain('SOUL.md');
  });

  it('leaves the symlink and its target untouched', async () => {
    const { repo, secret } = makeTree();
    const before = readFileSync(secret, 'utf-8');
    symlinkSync(secret, join(repo, 'SOUL.md'));

    await (new HardeningScanner() as any).createBackup(repo);

    expect(readFileSync(secret, 'utf-8')).toBe(before);
  });

  it('still backs up a real (non-symlinked) SOUL.md', async () => {
    // The mirror case: the #262 reason SOUL.md joined BACKUP_FILES must
    // survive. Skipping symlinks must not degrade into skipping the file.
    const { repo } = makeTree();
    writeFileSync(join(repo, 'SOUL.md'), '# SOUL\n\nreal governance file\n');

    const backupDir = await (new HardeningScanner() as any).createBackup(repo);
    const manifest = JSON.parse(
      readFileSync(join(backupDir as string, '.manifest.json'), 'utf-8'),
    );

    expect(manifest.existingFiles).toContain('SOUL.md');
    expect(readFileSync(join(backupDir as string, 'SOUL.md'), 'utf-8')).toContain('real governance file');
  });
});
