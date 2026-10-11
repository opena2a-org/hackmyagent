/**
 * #999 — under a CI or test-runner marker, what `telemetry on`, `telemetry
 * status` and `--version` print agrees with what the run does, and says why.
 *
 * Measured before the fix, with CI=true: `telemetry on` printed `state: on`,
 * the `telemetry status` after it printed `state: off`, and no event was sent
 * either way; `--version` printed `Telemetry: off` without a reason.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const REASON = 'CI is set, and usage telemetry is off under CI and test runners unless OPENA2A_TELEMETRY=on is set for the run';

interface Home { HOME: string; XDG_CONFIG_HOME: string }

function freshHome(): Home {
  return { HOME: tempDir('hma-999-home-'), XDG_CONFIG_HOME: tempDir('hma-999-xdg-') };
}

function cli(args: string[], home: Home): { stdout: string; stderr: string; status: number | null } {
  const env: NodeJS.ProcessEnv = { ...process.env, ...home, NO_COLOR: '1', CI: 'true' };
  delete env.OPENA2A_TELEMETRY;
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60_000, env });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status };
}

describe('telemetry under a CI marker says it is off, and why (#999)', { timeout: 120_000 }, () => {
  it('RED-ON-BASE: `telemetry on` and the `telemetry status` after it print the same state and the reason', () => {
    const home = freshHome();
    const on = cli(['telemetry', 'on'], home);
    expect(on.status, on.stderr).toBe(0);
    expect(on.stdout).toMatch(/state:\s+off/);
    expect(on.stdout).toContain(`why off:     ${REASON}`);

    const status = cli(['telemetry', 'status'], home);
    expect(status.stdout).toMatch(/state:\s+off/);
    expect(status.stdout).toContain(`why off:     ${REASON}`);
  });

  it('RED-ON-BASE: --version says why telemetry is off', () => {
    const r = cli(['--version'], freshHome());
    expect(r.status).toBe(0);
    expect(r.stderr).toContain(`Telemetry: off (${REASON}`);
  });

  it('names no marker as the reason when `telemetry off` is what keeps it off', () => {
    const home = freshHome();
    expect(cli(['telemetry', 'off'], home).stdout).not.toContain('why off');
    expect(cli(['telemetry', 'status'], home).stdout).not.toContain('why off');
    const version = cli(['--version'], home);
    expect(version.stderr).toMatch(/Telemetry: off \(opt-out:/);
    expect(version.stderr).not.toContain('CI is set');
  });
});
