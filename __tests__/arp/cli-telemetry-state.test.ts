/**
 * The ARP CLI's telemetry help and status describe the channel the way the
 * bundled SDK runs it.
 *
 * `src/arp/` re-exports `@opena2a/aim-sdk/arp`, and from aim-sdk 1.2.0 the
 * structural-signature channel is off until AIM_TELEMETRY=1 or
 * `signatureTelemetry.enabled: true` turns it on. The help still said
 * "Structural signatures are DEFAULT-ON"; `telemetry status` on a clean machine
 * printed `State: OFF (opted out)` and `Opted out by: local opt-out marker`
 * with no marker present; and `telemetry opt-in` printed "Structural signature
 * telemetry is ON (default)" while the channel stayed off.
 *
 * Each case runs the CLI with a scrubbed environment and a fresh HOME, so a
 * marker or an OPENA2A_TELEMETRY* / AIM_TELEMETRY variable on the machine
 * running the suite cannot decide the result, and compares the `State:` line
 * with the one the SDK's own aim-arp program prints for the same environment.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const ARP_CLI_SRC = path.join(REPO_ROOT, 'src', 'arp', 'cli', 'index.ts');
const ARP_CLI_DIST = path.join(REPO_ROOT, 'dist', 'arp', 'cli', 'index.js');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
const SDK_DIR = path.join(REPO_ROOT, 'node_modules', '@opena2a', 'aim-sdk');

type Env = Record<string, string>;

/** A fresh HOME, with the opt-out marker written into it when asked. */
function home(withMarker = false): string {
  const dir = tempDir('arp-tel-');
  if (withMarker) run(['telemetry', 'opt-out', '--no-purge'], dir);
  return dir;
}

function exec(file: string, args: string[], homeDir: string, extra: Env): string {
  return execFileSync(file, args, {
    cwd: homeDir,
    env: { HOME: homeDir, PATH: process.env.PATH ?? '', ...extra },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 60_000,
  });
}

/** The built ARP CLI when there is one, else the source through tsx. */
function run(args: string[], homeDir: string, extra: Env = {}): string {
  if (existsSync(ARP_CLI_DIST)) return exec(process.execPath, [ARP_CLI_DIST, ...args], homeDir, extra);
  if (!existsSync(TSX)) throw new Error('Neither dist/arp/cli/index.js nor node_modules/.bin/tsx is present; run `npm ci` first.');
  return exec(TSX, [ARP_CLI_SRC, ...args], homeDir, extra);
}

/** The bundled SDK's own telemetry CLI, the reference for what the channel does. */
function aimArp(args: string[], homeDir: string, extra: Env = {}): string {
  const sdk = JSON.parse(readFileSync(path.join(SDK_DIR, 'package.json'), 'utf8')) as { bin: Record<string, string> };
  return exec(process.execPath, [path.join(SDK_DIR, sdk.bin['aim-arp']), ...args], homeDir, extra);
}

const stateLine = (out: string) => /^ {2}State: +(.+)$/m.exec(out)?.[1];

describe('ARP CLI telemetry status names the state the bundled SDK runs', () => {
  const cases: Array<{ name: string; marker: boolean; env: Env; state: string; reason: RegExp | null }> = [
    { name: 'a clean machine', marker: false, env: {}, state: 'OFF (not turned on)', reason: null },
    { name: 'AIM_TELEMETRY=1', marker: false, env: { AIM_TELEMETRY: '1' }, state: 'ON', reason: null },
    {
      name: 'the opt-out marker',
      marker: true,
      env: {},
      state: 'OFF (opted out)',
      reason: /Opted out by: local opt-out marker \(.+ telemetry opt-in to clear\)/,
    },
    {
      name: 'OPENA2A_TELEMETRY=off',
      marker: false,
      env: { OPENA2A_TELEMETRY: 'off' },
      state: 'OFF (opted out)',
      reason: /Opted out by: environment variable \(OPENA2A_TELEMETRY; unset it to clear\)/,
    },
    {
      name: 'ARP_TELEMETRY_DISABLED=1 beside AIM_TELEMETRY=1',
      marker: false,
      env: { ARP_TELEMETRY_DISABLED: '1', AIM_TELEMETRY: '1' },
      state: 'OFF (opted out)',
      reason: /Opted out by: environment variable \(ARP_TELEMETRY_DISABLED; unset it to clear\)/,
    },
  ];

  for (const c of cases) {
    it(`on ${c.name}: ${c.state}`, () => {
      const dir = home(c.marker);
      const out = run(['telemetry', 'status'], dir, c.env);
      expect(stateLine(out), out).toBe(c.state);
      expect(stateLine(out)).toBe(stateLine(aimArp(['telemetry', 'status'], dir, c.env)));
      if (c.reason) expect(out).toMatch(c.reason);
      else expect(out).not.toMatch(/Opted out by|opt-out marker/);
    });
  }

  it('says how to turn the channel on when nobody has, and offers no opt-in for an opt-out that was never set', () => {
    const out = run(['telemetry', 'status'], home());
    expect(out).toContain('Turn on with: AIM_TELEMETRY=1 (or signatureTelemetry.enabled: true)');
    expect(out).toContain('Turn on:         AIM_TELEMETRY=1');
    expect(out).not.toContain('Opt back in:');
  });
});

describe('ARP CLI telemetry opt-in and help do not call the channel default-on', () => {
  it('opt-in on a clean machine says the channel stays off until turned on', () => {
    const out = run(['telemetry', 'opt-in'], home());
    expect(out).toContain('This channel stays OFF until you turn it on:');
    expect(out).toContain('AIM_TELEMETRY=1 (or signatureTelemetry.enabled: true)');
    expect(out).not.toMatch(/telemetry is ON/);
  });

  it('opt-in after an opt-out, with AIM_TELEMETRY=1, says the channel is on', () => {
    const dir = home(true);
    const out = run(['telemetry', 'opt-in'], dir, { AIM_TELEMETRY: '1' });
    expect(out).toContain('Structural signature telemetry is ON.');
    expect(stateLine(run(['telemetry', 'status'], dir, { AIM_TELEMETRY: '1' }))).toBe('ON');
  });

  it('opt-in under OPENA2A_TELEMETRY=off names that variable as what still disables it', () => {
    const out = run(['telemetry', 'opt-in'], home(), { OPENA2A_TELEMETRY: 'off' });
    expect(out).toContain('telemetry is still disabled by an env var or config');
    expect(out).toContain('OPENA2A_TELEMETRY=off');
  });

  it('the help says the channel is off unless turned on, and that opt-in does not turn it on', () => {
    const out = run(['telemetry', '--help'], home());
    expect(out).not.toMatch(/default-on/i);
    expect(out).toContain('Structural signatures are OFF unless you turn them on with AIM_TELEMETRY=1');
    expect(out).toMatch(/opt-in +Remove the local opt-out marker \(does not turn the channel on\)/);
  });

  it('register on a channel nobody turned on says no reports will be sent', () => {
    // Port 9 on loopback refuses the connection, so enrollment fails at once
    // and the note printed before it is what is checked.
    const out = run(['telemetry', 'register'], home(), { OPENA2A_REGISTRY_URL: 'http://127.0.0.1:9' });
    expect(out).toContain('NOTE: this channel is OFF until you turn it on, so no reports will be');
    expect(out).toContain('Turn on with: AIM_TELEMETRY=1 (or signatureTelemetry.enabled: true)');
  });
});
