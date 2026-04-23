// Regression test for CA-034 round 2: `hackmyagent check <bare-name>` emits
// the canonical NotFoundOutput shape on npm misses instead of the legacy
// "Invalid skill identifier" stderr error. Covers the bare-name reclassifier
// at src/cli.ts and the buildNotFoundOutput adoption on the npm miss path.
//
// Spawned test — needs a built dist/cli.js and network access to npm.
// Skipped on CI runners since the intent is local regression coverage for
// the shape, not a live-npm dependency in CI.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const BARE_NAME = 'totally-nonexistent-pkg-xyz789';
const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

function canRun(): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  return existsSync(CLI);
}

describe('check <bare-name> --json emits NotFoundOutput shape', () => {
  it.runIf(canRun())('returns canonical not-found JSON for a bare npm miss', () => {
    const res = spawnSync('node', [CLI, 'check', BARE_NAME, '--json', '--ci'], {
      encoding: 'utf8',
      timeout: 30_000,
    });

    expect(res.status).toBe(1);

    const stdout = (res.stdout || '').trim();
    expect(stdout.length).toBeGreaterThan(0);

    const parsed = JSON.parse(stdout);
    expect(parsed.name).toBe(BARE_NAME);
    expect(parsed.found).toBe(false);
    expect(parsed.ecosystem).toBe('npm');
    expect(typeof parsed.error).toBe('string');
    expect(parsed.error.length).toBeGreaterThan(0);
  });
});
