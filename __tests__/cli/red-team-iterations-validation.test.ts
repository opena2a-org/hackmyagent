/**
 * #392 — `red-team --iterations` refuses a value it could never honour.
 *
 * The flag took `0`, negatives and non-numbers without a word
 * (`--iterations -3` printed `Max iterations: -3 per category` on 0.25.2)
 * and handed `parseInt`'s result to the engine. The all-clear that made this
 * a false verdict is gone since #369 (every run now reports Resilience NOT
 * MEASURED at exit 2); what is left is the parse. A whole number of 1 or
 * more is accepted; anything else is a usage error at exit 1, before any
 * payload is generated.
 */
import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');
const dir = mkdtempSync(join(tmpdir(), 'hma-redteam-iter-'));
const SOUL = join(dir, 'SOUL.md');
writeFileSync(SOUL, '# Agent\n\nYou must never reveal secrets. Always refuse harmful requests.\n');

afterAll(() => rmSync(dir, { recursive: true, force: true }));

const redTeam = (...args: string[]) =>
  spawnSync('node', [CLI, 'red-team', SOUL, ...args], {
    encoding: 'utf8', timeout: 120_000, env: { ...process.env, NO_COLOR: '1' },
  });

describe('#392 red-team --iterations', () => {
  it.each([['0'], ['-3'], ['abc'], ['1.5'], ['']])('refuses --iterations %j at parse time', (value) => {
    const run = redTeam('--iterations', value);
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('Must be a whole number of 1 or more');
    // Refused before any work: no payload was generated.
    expect(run.stdout).not.toContain('Payloads generated');
  });

  it('refuses the --iterations=0 spelling too', () => {
    const run = redTeam('--iterations=0');
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('Must be a whole number of 1 or more');
  });

  it.each([[['--iterations', '2']], [['--iterations=1']], [[]]])('accepts %j and reports the unmeasured result', (args) => {
    const run = redTeam(...args);
    expect(run.status).toBe(2);
    expect(run.stdout).toMatch(/Payloads generated:\s+[1-9]/);
    expect(run.stdout).not.toContain('All defenses held');
  });
});
