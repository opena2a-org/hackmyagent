/**
 * #1111 — three items from a fresh-install walkthrough of the CLI.
 *
 * Measured before the fix, on the built CLI:
 *   - `telemetry bogus` printed `Unknown action 'bogus'` and exited 0;
 *   - three `secure <dir> --json` runs printed no contribution tip, yet the
 *     third stored `contributePromptDismissedAt`, so the tip's 30-day cooldown
 *     started on a run that never showed it;
 *   - `red-team <SOUL.md>` printed the truncated label `Governance ment.:`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

function cli(args: string[], extraEnv: NodeJS.ProcessEnv = {}): { stdout: string; stderr: string; status: number | null } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: tempDir('hma-1111-home-'),
    NO_COLOR: '1',
    ...extraEnv,
  };
  delete env.OPENA2A_TELEMETRY;
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120_000, env });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status };
}

describe('#1111 fresh-install walkthrough items', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: `telemetry <unknown action>` exits 1 and says so on stderr', () => {
    const r = cli(['telemetry', 'bogus']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Unknown action 'bogus'");
    expect(r.stdout).not.toContain('Unknown action');
  });

  it('`telemetry status` still exits 0', () => {
    const r = cli(['telemetry', 'status']);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/state:/);
  });

  it('RED-ON-BASE: `secure --json` runs count the scan but do not start the tip cooldown', () => {
    const target = tempDir('hma-1111-target-');
    const opena2aHome = tempDir('hma-1111-oa-');
    for (let i = 0; i < 3; i++) {
      const r = cli(['secure', target, '--json'], { OPENA2A_HOME: opena2aHome });
      expect(r.stdout).not.toContain('Tip: Your scans help build community trust data');
    }
    const config = JSON.parse(readFileSync(join(opena2aHome, 'config.json'), 'utf-8'));
    // The count proves the contribution path ran on each of the three runs.
    expect(config.telemetry.scanCount).toBe(3);
    expect(config.telemetry.contributePromptDismissedAt).toBeUndefined();
  });

  it('RED-ON-BASE: `red-team` prints the governance label in full', () => {
    const dir = tempDir('hma-1111-rt-');
    const target = join(dir, 'SOUL.md');
    writeFileSync(target, '# Agent\nYou are a helpful bot.\n');
    const r = cli(['red-team', target]);
    const out = `${r.stdout}${r.stderr}`;
    expect(out).toContain('  Governance terms:  ');
    expect(out).not.toContain('Governance ment.');
  });
});
