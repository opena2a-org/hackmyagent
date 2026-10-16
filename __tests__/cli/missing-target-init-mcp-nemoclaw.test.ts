/**
 * `init-mcp` and `secure-nemoclaw` on a target that is not a usable directory
 * end the way `secure` does on a missing one: not measured, exit 2, and the
 * reason on stderr with a runnable `Verify:` line.
 *
 * RED-ON-BASE: on ca50537c `init-mcp <missing>` exited 0 and created the
 * missing directory to hold the client file it wrote there, and
 * `secure-nemoclaw <missing>` exited 0 with `Risk Level: Low` and
 * `Checks: 1 total | 1 issue`, a risk level for a directory that was never on
 * disk.
 *
 * Each run gets a fresh HOME, so `secure-nemoclaw` cannot fall back to a real
 * `~/.nemoclaw`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir as tmp } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

function run(args: string[]) {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tmp('hma-missing-home-') };
  delete env.ANTHROPIC_API_KEY;
  delete env.OPENAI_API_KEY;
  delete env.CI;
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120_000, env });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('init-mcp on a target that is not a directory writes nothing, exit 2', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: a missing directory is refused and not created', () => {
    const missing = path.join(tmp('hma-initmcp-'), 'does-not-exist');
    const r = run(['init-mcp', missing]);
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toContain('does not exist, so nothing was written.');
    expect(r.stderr).toContain('Verify: ls -ld');
    expect(fs.existsSync(missing)).toBe(false);
    for (const line of ['Detected:', 'Added', 'Updated', 'Roots it may read:']) {
      expect(r.stdout + r.stderr).not.toContain(line);
    }
  });

  it('a file is refused and left unchanged', () => {
    const file = path.join(tmp('hma-initmcp-file-'), 'afile');
    fs.writeFileSync(file, 'unchanged\n');
    const r = run(['init-mcp', file]);
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toContain('is not a directory, so nothing was written.');
    expect(fs.readFileSync(file, 'utf8')).toBe('unchanged\n');
    expect(r.stdout + r.stderr).not.toContain('Added');
  });

  it('CONTROL: an existing empty directory is configured, exit 0', () => {
    const dir = tmp('hma-initmcp-ok-');
    const r = run(['init-mcp', dir, '--tool', 'claude']);
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toContain('.mcp.json');
    expect(fs.existsSync(path.join(dir, '.mcp.json'))).toBe(true);
  });
});

describe('secure-nemoclaw on a target that is not a directory reports no risk level, exit 2', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: a missing directory is not measured, and no risk level or check count prints', () => {
    const missing = path.join(tmp('hma-nemoclaw-'), 'does-not-exist');
    const r = run(['secure-nemoclaw', missing]);
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toContain('does not exist, so nothing was scanned.');
    expect(r.stderr).toContain('Verify: ls -ld');
    expect(r.stdout + r.stderr).not.toContain('Risk Level');
    expect(r.stdout + r.stderr).not.toContain('Checks:');
  });

  it('RED-ON-BASE: --json writes the not-measured document', () => {
    const missing = path.join(tmp('hma-nemoclaw-json-'), 'does-not-exist');
    const r = run(['secure-nemoclaw', missing, '--json']);
    expect(r.status, r.stderr).toBe(2);
    const doc = JSON.parse(r.stdout);
    expect(doc.target).toBe(missing);
    expect(doc.measured).toBe(false);
    expect(doc.verdict).toBeNull();
    expect(doc.exitCode).toBe(2);
    expect(doc.coverage.measured).toBe(false);
    expect(doc.coverage.reason).toBe('target-not-found');
    expect(doc.riskLevel ?? null).toBeNull();
    expect(doc).not.toHaveProperty('totalChecks');
    expect(doc).not.toHaveProperty('issues');
  });

  it('a file is refused with the not-a-directory line', () => {
    const file = path.join(tmp('hma-nemoclaw-file-'), 'afile');
    fs.writeFileSync(file, 'unchanged\n');
    const r = run(['secure-nemoclaw', file]);
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toContain('is not a directory, so nothing was scanned.');
    expect(r.stdout + r.stderr).not.toContain('Risk Level');
  });

  it('CONTROL: an existing empty directory is scanned', () => {
    const dir = tmp('hma-nemoclaw-ok-');
    const r = run(['secure-nemoclaw', dir]);
    expect(r.stdout, r.stderr).toContain('Scanning');
  });
});
