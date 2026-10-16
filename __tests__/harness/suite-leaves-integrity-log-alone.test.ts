/**
 * #1123: CLI runs spawned by this suite do not append to the developer's
 * NanoMind integrity event log.
 *
 * A CLI start appends an event to the log, by default
 * ~/.nanomind/integrity-events.jsonl. A spawn that inherits the worker's
 * environment inherits its HOME, so a run of the suite appended to the log of
 * whoever ran it, and parallel workers appended to it at the same time. One
 * run of the two deep-scan verdict test files appended 44 events there.
 * vitest.setup.ts gives each test file a log of its own through
 * NANOMIND_EVENT_CHAIN_PATH.
 *
 * Claims held here:
 *   - the worker carries an absolute NANOMIND_EVENT_CHAIN_PATH outside HOME;
 *   - a spawn that inherits it appends there and writes no log under HOME;
 *   - a spawn without it writes the log under HOME, so the check above can
 *     see a write there when there is one;
 *   - a relative value is ignored, so the log is never written under the
 *     directory the CLI runs in.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const LOG_UNDER_HOME = path.join('.nanomind', 'integrity-events.jsonl');

function eventCount(file: string): number {
  return existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean).length : 0;
}

function runVersion(env: NodeJS.ProcessEnv, cwd?: string): void {
  const r = spawnSync(process.execPath, [CLI, '--version'], { encoding: 'utf8', timeout: 60_000, env, cwd });
  expect(r.status, r.stderr).toBe(0);
}

describe('#1123 the suite keeps the integrity event log out of HOME', () => {
  it('the worker carries an absolute log path outside HOME', () => {
    const logPath = process.env.NANOMIND_EVENT_CHAIN_PATH;
    expect(logPath, 'vitest.setup.ts sets NANOMIND_EVENT_CHAIN_PATH').toBeTruthy();
    expect(path.isAbsolute(logPath!)).toBe(true);
    expect(path.relative(homedir(), logPath!).startsWith('..')).toBe(true);
  });

  it('a spawn that inherits the worker\'s environment appends to that path and writes no log under HOME', () => {
    const home = tempDir('hma-1123-home-');
    const logPath = process.env.NANOMIND_EVENT_CHAIN_PATH!;
    const before = eventCount(logPath);
    runVersion({ ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off' });
    expect(eventCount(logPath)).toBe(before + 1);
    expect(existsSync(path.join(home, LOG_UNDER_HOME))).toBe(false);
  });

  it('control: a spawn without the variable writes the log under HOME', () => {
    const home = tempDir('hma-1123-home-');
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off' };
    delete env.NANOMIND_EVENT_CHAIN_PATH;
    runVersion(env);
    expect(eventCount(path.join(home, LOG_UNDER_HOME))).toBe(1);
  });

  it('a relative value is ignored: the log goes under HOME, not under the working directory', () => {
    const home = tempDir('hma-1123-home-');
    const cwd = tempDir('hma-1123-cwd-');
    runVersion({ ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NANOMIND_EVENT_CHAIN_PATH: path.join('relative', 'events.jsonl') }, cwd);
    expect(eventCount(path.join(home, LOG_UNDER_HOME))).toBe(1);
    expect(existsSync(path.join(cwd, 'relative'))).toBe(false);
  });
});
