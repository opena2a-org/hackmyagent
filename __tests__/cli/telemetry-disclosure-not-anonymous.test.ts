/**
 * Usage telemetry is not described as anonymous.
 *
 * Every usage event carries a persistent install_id (a per-machine ID kept in
 * the telemetry config file and shown by `hackmyagent telemetry status`), so
 * calling the telemetry "anonymous" overstates what a user gets. The help
 * footer and the `telemetry` subcommand description are the two places this
 * CLI writes that claim itself; both must state the install ID instead.
 *
 * The disclosure has to survive the rewording: the footer must still say
 * telemetry is on, name the install ID, and give the opt-out.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// This suite spawns the built CLI; a binary older than `src/` would be
// measuring code that is no longer under test.
beforeAll(assertDistFreshIfPresent);

const CLI_PATH = resolve(__dirname, '../../dist/cli.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const XDG_CONFIG_HOME = mkdtempSync(join(tmpdir(), 'hma-telemetry-wording-'));

function run(args: string[]): { stdout: string; stderr: string; status: number } {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf8',
    timeout: 20000,
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', XDG_CONFIG_HOME },
  });
  return {
    stdout: (res.stdout ?? '').replace(STRIP_ANSI, ''),
    stderr: (res.stderr ?? '').replace(STRIP_ANSI, ''),
    status: res.status ?? 1,
  };
}

describe('usage telemetry wording', () => {
  it('dist/cli.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('--help does not call usage telemetry anonymous and still discloses it', () => {
    if (!existsSync(CLI_PATH)) return;
    const { stdout, stderr, status } = run(['--help']);
    expect(status).toBe(0);
    expect(stdout + stderr).not.toMatch(/anonymous/i);

    const footer = stdout.slice(stdout.indexOf('\nTelemetry:\n'));
    expect(footer).toMatch(/^\nTelemetry:\n/);
    expect(footer).toMatch(/Usage telemetry is on/);
    expect(footer).toMatch(/persistent install ID/);
    expect(footer).toMatch(/OPENA2A_TELEMETRY=off/);
  });

  it.each([
    ['telemetry', '--help'],
    ['help', 'telemetry'],
  ])('`%s %s` describes the subcommand without calling it anonymous', (...args) => {
    if (!existsSync(CLI_PATH)) return;
    const { stdout, stderr, status } = run(args);
    expect(status).toBe(0);
    expect(stdout).toMatch(/Inspect or toggle usage telemetry/);
    expect(stdout + stderr).not.toMatch(/anonymous/i);
  });
});
