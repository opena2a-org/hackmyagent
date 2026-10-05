/**
 * #389 — the `.gitignore` that `secure --fix` generates must exclude the backup
 * directory the same run writes.
 *
 * `--fix` redacts a live credential and keeps the pre-fix copy under
 * `.hackmyagent-backup/<stamp>/` so `rollback` can undo the run. The generated
 * `.gitignore` covered `.env`, `*.pem` and `*.key` but not that directory, so a
 * `git add -A` after `--fix` committed the plaintext credential the fix had just
 * removed from the live file.
 *
 * Asserted with `git check-ignore` and `git add --dry-run`, not a string match
 * on the file, so the test measures what git would actually commit.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

/** Synthesised at runtime — never a literal in the source tree. */
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;

/** Git with no inherited `GIT_*` and no global excludes, so only the tree's `.gitignore` decides. */
function git(dir: string, args: string[]) {
  return spawnSync('git', ['-c', 'core.excludesFile=/dev/null', '-C', dir, ...args], {
    env: gitFreeEnv(),
    encoding: 'utf-8',
  });
}

describe('#389 the .gitignore --fix generates excludes its own backup directory', () => {
  it('git ignores the backup copy of a redacted credential after --fix', async () => {
    const dir = tempDir('hma-389-');
    try {
      initThrowawayRepo(dir);
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      // Preconditions: this run generated the `.gitignore`, redacted the live
      // file, and left the plaintext in a backup copy. Without all three the
      // assertions below would measure nothing.
      expect(result.findings.find((f) => f.checkId === 'GIT-001')?.fixed).toBe(true);
      expect(await readFile(path.join(dir, 'config.json'), 'utf-8')).not.toContain(FAKE_GH_TOKEN);
      const stamps = await readdir(path.join(dir, '.hackmyagent-backup'));
      expect(stamps).toHaveLength(1);
      const backupCopy = path.posix.join('.hackmyagent-backup', stamps[0], 'config.json');
      expect(await readFile(path.join(dir, backupCopy), 'utf-8')).toContain(FAKE_GH_TOKEN);

      // One path per call: `check-ignore` exits 0 when ANY of its paths is ignored.
      for (const p of [backupCopy, '.hackmyagent-backup']) {
        const checked = git(dir, ['check-ignore', '-v', p]);
        expect(checked.status, `${p} is not ignored ${checked.stderr}`).toBe(0);
        expect(checked.stdout.startsWith('.gitignore:'), checked.stdout).toBe(true);
      }

      const staged = git(dir, ['add', '--dry-run', '-A']);
      expect(staged.status, staged.stderr).toBe(0);
      expect(staged.stdout).toContain('config.json');
      expect(staged.stdout).not.toContain('.hackmyagent-backup');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
