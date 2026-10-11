/**
 * Usage telemetry is not described as anonymous.
 *
 * Every usage event carries a persistent install_id (a per-machine ID kept in
 * the telemetry config file and shown by `hackmyagent telemetry status`), so
 * calling the telemetry "anonymous" overstates what a user gets. The help
 * footer and the `telemetry` subcommand description are the two places this
 * CLI writes that claim itself; both must state the install ID instead.
 *
 * The disclosure has to survive the rewording: the footer must name the
 * install ID and, when telemetry is on, give the opt-out.
 *
 * The footer states the live on/off state, the same one `--version` prints on
 * stderr. It was a fixed "Usage telemetry is on" line, printed even under
 * OPENA2A_TELEMETRY=off (#986).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

// This suite spawns the built CLI; a binary older than `src/` would be
// measuring code that is no longer under test.
beforeAll(assertDistFreshIfPresent);

const CLI_PATH = resolve(__dirname, '../../dist/cli.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
// Made in a hook, not at module scope, which also runs under `vitest list`,
// where nothing would remove it.
let XDG_CONFIG_HOME = '';
beforeAll(() => {
  XDG_CONFIG_HOME = tempDir('hma-telemetry-wording-');
});

function run(
  args: string[],
  telemetry: 'off' | 'on' | 'unset' = 'off',
): { stdout: string; stderr: string; status: number } {
  const env: NodeJS.ProcessEnv = { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1', XDG_CONFIG_HOME };
  if (telemetry === 'off') {
    env.OPENA2A_TELEMETRY = 'off';
  } else {
    // A spawn from this suite carries the test runner's marker, so usage
    // telemetry is off unless OPENA2A_TELEMETRY=on is set for the run (#963).
    // Neither `--help` nor `--version` posts an event; the closed local
    // endpoint keeps it that way if one did.
    env.VITEST = 'true';
    if (telemetry === 'on') env.OPENA2A_TELEMETRY = 'on';
    else delete env.OPENA2A_TELEMETRY;
    env.OPENA2A_TELEMETRY_URL = 'http://127.0.0.1:9/';
  }
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf8',
    timeout: 20000,
    env,
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
    expect(footer).toMatch(/persistent install ID/);
  });

  it.each([
    ['off', 'off', /Usage telemetry is off/, /Usage telemetry is on/],
    ['on', 'on', /Usage telemetry is on\b.*Disable: OPENA2A_TELEMETRY=off/, /Usage telemetry is off/],
    ['unset', 'off', /Usage telemetry is off/, /Usage telemetry is on/],
  ] as const)('--help with OPENA2A_TELEMETRY %s under a test runner states usage telemetry is %s, as --version does', (setting, state, says, doesNotSay) => {
    if (!existsSync(CLI_PATH)) return;
    const help = run(['--help'], setting);
    expect(help.status).toBe(0);
    const footer = help.stdout.slice(help.stdout.indexOf('\nTelemetry:\n'));
    expect(footer).toMatch(says);
    expect(footer).not.toMatch(doesNotSay);
    expect(footer).toMatch(/off under CI and test runners .* unless OPENA2A_TELEMETRY=on/);

    const version = run(['--version'], setting);
    expect(version.status).toBe(0);
    expect(version.stderr).toMatch(new RegExp(`^Telemetry: ${state}\\b`, 'm'));
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
