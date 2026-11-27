/**
 * #505 — the Undo line standalone `harden-soul` prints has to be true.
 *
 * Measured before this change: `harden-soul` on a directory with no governance
 * file created SOUL.md and printed `Undo: hackmyagent rollback <dir>`, and
 * `rollback` then left SOUL.md in place, because the backup recorded nothing
 * the run created. A run that wrote nothing (every domain covered, or a
 * refused `--tier`) left an empty run in the backup store, and the next
 * `rollback` undid that empty run instead of the one before it.
 *
 * Runs the built CLI, as a user does, against a fresh directory per test.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { storeRuns } from '../helpers/backup-store';
import { tempDir } from '../helpers/temp-dir';

const TEST_TIMEOUT = 300_000;

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1' };
  delete env.ANTHROPIC_API_KEY;
  const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
    encoding: 'utf8', env, timeout: 240_000, maxBuffer: 64 * 1024 * 1024,
  });
  return { status: r.status, stdout: String(r.stdout ?? ''), stderr: String(r.stderr ?? '') };
}

function project(): string {
  const dir = tempDir('hma-505-undo-');
  writeFileSync(path.join(dir, 'package.json'), '{"name":"fx","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'README.md'), '# fx\n');
  return dir;
}

describe('#505 harden-soul undo', () => {
  beforeAll(assertDistFresh);

  it('rollback removes the SOUL.md harden-soul created, as its Undo line says', async () => {
    const dir = project();
    const soul = path.join(dir, 'SOUL.md');

    const harden = run(['harden-soul', dir]);
    expect(harden.status, harden.stderr).toBe(0);
    expect(existsSync(soul), 'harden-soul did not create SOUL.md; this test measures nothing').toBe(true);
    expect(harden.stdout).toMatch(/Undo:\s+\S+.*rollback/);
    expect(await storeRuns(dir)).toHaveLength(1);

    const rollback = run(['rollback', dir]);
    expect(rollback.status, rollback.stdout + rollback.stderr).toBe(0);
    expect(existsSync(soul)).toBe(false);
  }, TEST_TIMEOUT);

  it('keeps a created SOUL.md the user edited before rollback', () => {
    const dir = project();
    const soul = path.join(dir, 'SOUL.md');

    expect(run(['harden-soul', dir]).status).toBe(0);
    writeFileSync(soul, `${readFileSync(soul, 'utf8')}\n## Mine\n`);

    run(['rollback', dir]);
    expect(existsSync(soul)).toBe(true);
    expect(readFileSync(soul, 'utf8')).toContain('## Mine');
  }, TEST_TIMEOUT);

  it('a run with nothing to add leaves no backup and prints no Undo line', async () => {
    const dir = project();
    expect(run(['harden-soul', dir]).status).toBe(0);
    const runsAfterFirst = await storeRuns(dir);
    expect(runsAfterFirst).toHaveLength(1);
    const generated = readFileSync(path.join(dir, 'SOUL.md'), 'utf8');

    const second = run(['harden-soul', dir]);
    expect(second.status, second.stderr).toBe(0);
    expect(readFileSync(path.join(dir, 'SOUL.md'), 'utf8'), 'the second run changed SOUL.md; this test measures nothing').toBe(generated);
    expect(second.stdout).not.toMatch(/Undo:/);
    expect(await storeRuns(dir)).toEqual(runsAfterFirst);

    // The rollback after the no-op run undoes the run that created SOUL.md.
    const rollback = run(['rollback', dir]);
    expect(rollback.status, rollback.stdout + rollback.stderr).toBe(0);
    expect(existsSync(path.join(dir, 'SOUL.md'))).toBe(false);
  }, TEST_TIMEOUT);

  it('a refused --tier leaves no backup behind', async () => {
    const dir = project();
    const body = '# Soul\n\n<!-- soul:tier=BASIC -->\n\nBe helpful.\n';
    writeFileSync(path.join(dir, 'SOUL.md'), body);

    const refused = run(['harden-soul', dir, '--tier', 'AGENTIC']);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/conflicts with the tier marker/);
    expect(readFileSync(path.join(dir, 'SOUL.md'), 'utf8')).toBe(body);
    expect(await storeRuns(dir)).toEqual([]);
  }, TEST_TIMEOUT);
});
