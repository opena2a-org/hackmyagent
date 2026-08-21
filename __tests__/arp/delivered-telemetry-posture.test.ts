import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * `hackmyagent/arp` is a thin re-export of `@opena2a/aim-sdk/arp` (src/arp/index.ts,
 * #249), so the runtime-protection behaviour hackmyagent DELIVERS — including whether
 * the structural-signature telemetry channel is on by default — is decided entirely by
 * the aim-sdk version the pin in package.json resolves to. aim-sdk 1.2.0 made that
 * channel opt-in and honors the documented `OPENA2A_TELEMETRY=off` opt-out
 * (GHSA-r2hq-x5w4-5v63); earlier versions were default-on and read neither.
 *
 * These tests pin the PROPERTY, not the version number: they probe the installed
 * dependency the way a consumer's process would, and fail if a future pin change
 * regresses the delivered posture — whatever version string it carries.
 *
 * Probes run in a child process with a scrubbed env and a fresh empty HOME, for two
 * reasons learned the hard way:
 * - `~/.opena2a/telemetry-optout` on a developer machine makes every posture read
 *   `false`, silently inverting the measurement. A fresh HOME removes it.
 * - Inherited `OPENA2A_TELEMETRY*` / `AIM_TELEMETRY` / `ARP_TELEMETRY_DISABLED` vars
 *   in the runner's env would leak into the probe. Passing an explicit env object
 *   scrubs them.
 */
const repoRoot = join(__dirname, '..', '..');

function probePosture(extraEnv: Record<string, string> = {}): string {
  const cleanHome = mkdtempSync(join(tmpdir(), 'arp-posture-'));
  return execFileSync(
    process.execPath,
    ['-e', "process.stdout.write(String(require('@opena2a/aim-sdk/arp').signatureTelemetryEnabled()))"],
    {
      cwd: repoRoot,
      env: { HOME: cleanHome, PATH: process.env.PATH ?? '', ...extraEnv },
      encoding: 'utf8',
    },
  );
}

describe('the telemetry posture hackmyagent delivers through its arp re-export', () => {
  it('is OFF by default on a clean machine', () => {
    expect(probePosture()).toBe('false');
  });

  it('honors the documented opt-out spelling, OPENA2A_TELEMETRY=off', () => {
    expect(probePosture({ OPENA2A_TELEMETRY: 'off' })).toBe('false');
  });

  it('turns on only under an explicit opt-in — and the probe can see "true", so the two tests above are not vacuous', () => {
    // Non-vacuity control: a probe that failed to load the module would throw, but a
    // probe reading the wrong state could report 'false' forever. This asserts the
    // discriminating direction: the same probe, given the opt-in, reads 'true'.
    expect(probePosture({ AIM_TELEMETRY: '1' })).toBe('true');
  });

  it('and an opt-out beats the opt-in when both are set', () => {
    expect(probePosture({ AIM_TELEMETRY: '1', OPENA2A_TELEMETRY: 'off' })).toBe('false');
  });
});
