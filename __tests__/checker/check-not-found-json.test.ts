// Regression tests for HMA --json not-found path canonical shape (CA-034 round 2).
//
// Two layers:
// 1. Deterministic unit test — calls `buildNotFoundOutput` with the exact
//    arguments cli.ts uses, asserts the wire shape matches the parity
//    fixtures' must_match contract. No spawn, no network, runs everywhere.
// 2. Spawned smoke test — invokes the built `dist/cli.js` against a
//    non-existent npm package and a non-existent GitHub repo, asserts the
//    JSON output. Skipped on CI runners since the harness needs network +
//    a built dist.
//
// The unit layer is the contract gate (closes F3 + F4). The spawn layer
// is local-only confirmation that the wiring in cli.ts is reaching the
// builder.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { buildNotFoundOutput } from '@opena2a/check-core';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

function canRunSpawn(): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  return existsSync(CLI);
}

describe('check --json not-found shape (deterministic — closes F3 + F4 contract)', () => {
  it('F3: bare-name npm miss produces NotFoundOutput shape', () => {
    // Mirrors the exact call site in cli.ts for the bare-name reclass at
    // the npm-404 fallthrough.
    const skill = 'opena2a-parity-f2-nonexistent-pkg-xyz789';
    const out = buildNotFoundOutput({
      name: skill,
      ecosystem: 'npm',
      error: `Package "${skill}" not found on npm.`,
    });

    expect(out.name).toBe(skill);
    expect(out.found).toBe(false);
    expect(out.ecosystem).toBe('npm');
    expect(typeof out.error).toBe('string');
    expect(out.error?.length ?? 0).toBeGreaterThan(0);
  });

  it('F4: github 404 populates errorHint (was undefined pre-0.20.1)', () => {
    // Mirrors the exact call site in cli.ts for the GitHub 404 branch in
    // checkGitHubRepo. errorHint must thread through to the JSON branch.
    const displayName = 'anthropic/code-review';
    const errorHint = `Verify the URL: https://github.com/${displayName}`;
    const out = buildNotFoundOutput({
      name: displayName,
      ecosystem: 'github',
      error: `Repository "${displayName}" not found on GitHub.`,
      errorHint,
    });

    expect(out.name).toBe(displayName);
    expect(out.found).toBe(false);
    expect(out.ecosystem).toBe('github');
    expect(out.errorHint).toBe(errorHint);
  });

  it('PyPI 404 produces NotFoundOutput shape', () => {
    const name = 'opena2a-parity-pypi-nonexistent-xyz789';
    const out = buildNotFoundOutput({
      name,
      ecosystem: 'pypi',
      error: `Package "${name}" not found on PyPI.`,
    });

    expect(out.name).toBe(name);
    expect(out.found).toBe(false);
    expect(out.ecosystem).toBe('pypi');
  });

  it('npm translateDownloadError path threads suggestions + errorHint', () => {
    const name = 'lodahs';
    const errorHint = 'Did you mean "lodash"?';
    const suggestions = ['lodash', 'lodash.merge'];
    const out = buildNotFoundOutput({
      name,
      ecosystem: 'npm',
      error: errorHint,
      errorHint,
      suggestions,
    });

    expect(out.name).toBe(name);
    expect(out.ecosystem).toBe('npm');
    expect(out.errorHint).toBe(errorHint);
    expect(out.suggestions).toEqual(suggestions);
  });
});

describe('check --json not-found wired through dist/cli.js (smoke, local-only)', () => {
  it.runIf(canRunSpawn())('F3: bare-name miss emits NotFoundOutput from cli.ts (no stderr fall-through)', () => {
    const bareName = 'totally-nonexistent-pkg-xyz789';
    const res = spawnSync('node', [CLI, 'check', bareName, '--no-scan', '--json', '--ci'], {
      encoding: 'utf8',
      timeout: 30_000,
    });

    expect(res.status).toBe(1);
    const stdout = (res.stdout || '').trim();
    expect(stdout.length).toBeGreaterThan(0);

    const parsed = JSON.parse(stdout);
    expect(parsed.name).toBe(bareName);
    expect(parsed.found).toBe(false);
    expect(parsed.ecosystem).toBe('npm');
    expect(typeof parsed.error).toBe('string');
    expect(parsed.error.length).toBeGreaterThan(0);
  });

  it.runIf(canRunSpawn())('F4: git-style miss populates errorHint in JSON output', () => {
    const target = 'anthropic/code-review';
    const res = spawnSync('node', [CLI, 'check', target, '--no-scan', '--json', '--ci'], {
      encoding: 'utf8',
      timeout: 30_000,
    });

    expect(res.status).toBe(1);
    const stdout = (res.stdout || '').trim();
    expect(stdout.length).toBeGreaterThan(0);

    const parsed = JSON.parse(stdout);
    expect(parsed.name).toBe(target);
    expect(parsed.found).toBe(false);
    expect(parsed.ecosystem).toBe('github');
    expect(parsed.errorHint).toBe(`Verify the URL: https://github.com/${target}`);
  });
});
