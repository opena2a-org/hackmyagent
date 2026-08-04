// `rollback` must remove every file the fix GENERATED, including the ones no
// finding names.
//
// #262 gave the backup manifest a v2 shape: only a path observed MISSING when
// the backup was taken can be recorded as created, and deletion requires a
// sha256 match. Its candidate list, though, was derived from the findings —
// `f.fixed && f.file` — which quietly assumes every file a fix writes is
// named by some finding.
//
// `.env.example` is written by the `CRED-001` fix while that finding's `file`
// names the config it EDITED. So the generated file reached no candidate
// list, and `rollback` left it behind while reporting completeness:
//
//   [+] Rollback complete
//      Restored 2 modified files, removed 1 generated file.
//   $ ls
//   .env.example  config.json  package.json      <- .env.example survives
//
// That is the same overstatement #262 was filed against, one attribution
// layer down. Candidates now come from the writes themselves, so a fix with
// no owning finding cannot fall through the gap again.
//
// The fail-safe direction is unchanged and pinned below: widening the
// candidate list must not let rollback delete something the user wrote.

import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync, readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const dirs: string[] = [];

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A tree whose CRED-001 fix generates `.env.example` as a side effect. */
function makeFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-rbwrite-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'package.json'), '{"name":"rb","version":"1.0.0"}\n');
  writeFileSync(
    join(dir, 'config.json'),
    JSON.stringify({ apiKey: `sk-ant-api03-${'A'.repeat(24)}` }) + '\n',
  );
  return dir;
}

function run(dir: string, args: string[]) {
  return spawnSync('node', [CLI, ...args], {
    cwd: dir, encoding: 'utf8', timeout: 180_000,
    env: { ...process.env, NO_COLOR: '1' },
  });
}

function manifestOf(dir: string): { createdFiles: { path: string }[]; absentAtBackup: string[] } {
  const backupRoot = join(dir, '.hackmyagent-backup');
  const stamp = readdirSync(backupRoot)[0];
  return JSON.parse(readFileSync(join(backupRoot, stamp, '.manifest.json'), 'utf8'));
}

describe('rollback covers fix writes no finding names', { timeout: 240_000 }, () => {
  it('records and removes a generated `.env.example`', () => {
    if (!existsSync(CLI)) return;
    const dir = makeFixture();

    run(dir, ['secure', '.', '--fix']);

    // Precondition: the fix really did generate it, and the backup really did
    // observe it missing. Without both the assertion below passes vacuously.
    expect(existsSync(join(dir, '.env.example'))).toBe(true);
    const manifest = manifestOf(dir);
    expect(manifest.absentAtBackup).toContain('.env.example');

    // The contract. Pre-fix `createdFiles` held only `.gitignore`.
    expect(manifest.createdFiles.map(c => c.path)).toContain('.env.example');

    run(dir, ['rollback', '.']);
    expect(existsSync(join(dir, '.env.example'))).toBe(false);
  });

  it('still refuses to delete a file the user wrote after the fix', () => {
    if (!existsSync(CLI)) return;
    const dir = makeFixture();

    run(dir, ['secure', '.', '--fix']);

    // The user edits the generated file between --fix and rollback. The
    // sha256 guard must keep it: widening the candidate list must not widen
    // what rollback is willing to destroy.
    const userContent = '# hand-written, must survive\nSTRIPE_KEY=\n';
    writeFileSync(join(dir, '.env.example'), userContent);

    run(dir, ['rollback', '.']);

    expect(existsSync(join(dir, '.env.example'))).toBe(true);
    expect(readFileSync(join(dir, '.env.example'), 'utf8')).toBe(userContent);
  });
});
