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
 * #376 — `--fix` no longer writes that directory: its copies go to the backup
 * store outside the tree. The entry stays, for the directory earlier versions
 * left behind, which still holds the plaintext until the user deletes it.
 *
 * Asserted with `git check-ignore` and `git add --dry-run`, not a string match
 * on the file, so the test measures what git would actually commit.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';
import { latestStoreRun } from '../helpers/backup-store';
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
  it('git ignores a backup an earlier version left in the tree, and --fix adds none of its own', async () => {
    const dir = tempDir('hma-389-');
    try {
      initThrowawayRepo(dir);
      await writeFile(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}\n');
      await writeFile(path.join(dir, 'config.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
      // #376 — `--fix` keeps its copies in the backup store, outside the tree.
      // The directory this entry is for is the one 0.25.x to 0.33.x wrote into
      // the tree, which stays there until the user deletes it and still holds
      // the plaintext those versions redacted from the live file.
      const backupCopy = path.posix.join('.hackmyagent-backup', '2026-01-01-000000', 'config.json');
      await mkdir(path.dirname(path.join(dir, backupCopy)), { recursive: true });
      await writeFile(path.join(dir, backupCopy), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');

      const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      // Preconditions: this run generated the `.gitignore`, redacted the live
      // file, and kept its own copy outside the tree. The earlier version's
      // copy is still in the tree with the plaintext in it. Without all of
      // these the assertions below would measure nothing.
      expect(result.findings.find((f) => f.checkId === 'GIT-001')?.fixed).toBe(true);
      expect(await readFile(path.join(dir, 'config.json'), 'utf-8')).not.toContain(FAKE_GH_TOKEN);
      expect(await readFile(path.join(await latestStoreRun(dir), 'config.json'), 'utf-8')).toContain(FAKE_GH_TOKEN);
      expect(await readdir(path.join(dir, '.hackmyagent-backup')), '--fix wrote a backup into the tree').toEqual(['2026-01-01-000000']);
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
