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
//
// hackmyagent#203: the three npm spawn cases used to shell out to the real
// `npm pack` against the live registry. Under full-suite parallel load npm
// returned a generic command-failed error instead of its E404 shape, so
// cli.ts took the unrecognized-error branch and the tests flaked. They now
// run against a PATH-injected `npm` shim that emits npm's real E404 stderr
// for `pack` and delegates every other subcommand to the real binary. That
// removes both the network and the parallelism from the equation while
// still exercising the full cli.ts routing path.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { buildNotFoundOutput } from '@opena2a/check-core';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

function canRunSpawn(): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  // The npm shim below is a POSIX sh script.
  if (process.platform === 'win32') return false;
  return existsSync(CLI);
}

/**
 * Absolute path to the real npm, resolved before the shim goes on PATH so
 * the shim can delegate non-`pack` subcommands without recursing into
 * itself.
 */
function resolveRealNpm(): string | undefined {
  const res = spawnSync('sh', ['-c', 'command -v npm'], { encoding: 'utf8' });
  const found = (res.stdout || '').trim();
  return found.length > 0 ? found : undefined;
}

let stubDir: string | undefined;
let stubBin: string | undefined;
let markerFile: string | undefined;

beforeAll(() => {
  if (!canRunSpawn()) return;
  const realNpm = resolveRealNpm();
  if (!realNpm) return;

  stubDir = mkdtempSync(join(tmpdir(), 'hma-npm-shim-'));
  stubBin = join(stubDir, 'npm');
  markerFile = join(stubDir, 'invocations.log');

  // `$name`, `$1`, `$@` are shell expansions, not template interpolation —
  // only `${` interpolates in a JS template literal.
  writeFileSync(
    stubBin,
    `#!/bin/sh
printf '%s\\n' "$*" >> "$HMA_TEST_NPM_SHIM_MARKER"
if [ "$1" = "pack" ]; then
  name="$2"
  cat >&2 <<EOF
npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/$name - Not found
npm error 404
npm error 404  '$name@*' is not in this registry.
EOF
  exit 1
fi
exec ${realNpm} "$@"
`,
    { mode: 0o755 },
  );
});

afterAll(() => {
  if (stubDir) rmSync(stubDir, { recursive: true, force: true });
});

/** Env for a spawned CLI run with the npm shim ahead of the real npm on PATH. */
function shimEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PATH: `${stubDir}${delimiter}${process.env.PATH ?? ''}`,
    HMA_TEST_NPM_SHIM_MARKER: markerFile!,
  };
}

/**
 * Non-vacuity guard. If PATH injection ever silently stops working the
 * spawned CLI would fall back to the real npm and these tests would pass
 * for the wrong reason (and flake again). Assert the shim actually served
 * the `pack` call under test.
 */
function expectShimServedPack(name: string): void {
  const log = existsSync(markerFile!) ? readFileSync(markerFile!, 'utf8') : '';
  expect(log).toContain(`pack ${name}`);
}

function resetMarker(): void {
  writeFileSync(markerFile!, '');
}

// --- Outbound-request recording, for the #195 gate (hackmyagent#397) --------
//
// The `#195` case used to gate on a 5-second wall clock. That number was a
// proxy for "no PyPI download happened", and a bad one: roughly two thirds of
// it was a live Registry round trip (`queryRegistry` -> https://api.oa2a.org,
// 5s client timeout), so the test measured the Registry's latency far more
// than it measured the behaviour under test, and went red on a slow link.
//
// The property is now measured directly. A `--require` preload records the
// host of every request the spawned CLI attempts, and the assertions read that
// log. Nothing is timed.
//
// Note for anyone extending this: a PATH-injected `pip` shim would NOT work
// here. HackMyAgent never spawns `pip` — `checkPyPiPackage` reaches PyPI
// through global `fetch`, and the only subprocesses on that path are `tar` and
// `unzip`, both below the `--no-scan` short-circuit. A `pip` shim would record
// nothing and its marker assertion would pass vacuously forever.
const NET_RECORDER = join(__dirname, '..', 'helpers', 'net-recorder.cjs');
let netDir: string | undefined;
let netMarker: string | undefined;

beforeAll(() => {
  if (!canRunSpawn()) return;
  netDir = mkdtempSync(join(tmpdir(), 'hma-net-rec-'));
  netMarker = join(netDir, 'hosts.log');
  writeFileSync(netMarker, '');
});

afterAll(() => {
  if (netDir) rmSync(netDir, { recursive: true, force: true });
});

function netEnv(): NodeJS.ProcessEnv {
  return { ...process.env, HMA_TEST_NET_MARKER: netMarker! };
}

function resetNetMarker(): void {
  writeFileSync(netMarker!, '');
}

function recordedHosts(): string[] {
  if (!netMarker || !existsSync(netMarker)) return [];
  return readFileSync(netMarker, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

function canRunNpmShimSpawn(): boolean {
  return canRunSpawn() && resolveRealNpm() !== undefined;
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

describe('check --json not-found wired through dist/cli.js (smoke, local-only)', { timeout: 60_000 }, () => {
  it.runIf(canRunNpmShimSpawn())('F3: bare-name miss emits NotFoundOutput from cli.ts (no stderr fall-through)', () => {
    const bareName = 'totally-nonexistent-pkg-xyz789';
    resetMarker();
    const res = spawnSync('node', [CLI, 'check', bareName, '--no-scan', '--json', '--ci'], {
      encoding: 'utf8',
      timeout: 30_000,
      env: shimEnv(),
    });

    expectShimServedPack(bareName);
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

  it.runIf(canRunNpmShimSpawn())('#161: uppercase bare-name miss routes to npm (not skill-id parser) and emits valid JSON', () => {
    const bareName = 'NONEXISTENT-XYZ-9999';
    resetMarker();
    const res = spawnSync('node', [CLI, 'check', bareName, '--no-scan', '--json', '--ci'], {
      encoding: 'utf8',
      timeout: 30_000,
      env: shimEnv(),
    });

    expectShimServedPack(bareName);
    expect(res.status).toBe(1);
    const stdout = (res.stdout || '').trim();
    expect(stdout.length).toBeGreaterThan(0);
    expect(res.stderr || '').not.toContain('Invalid skill identifier');

    const parsed = JSON.parse(stdout);
    expect(parsed.name).toBe(bareName);
    expect(parsed.found).toBe(false);
    expect(parsed.ecosystem).toBe('npm');
    expect(parsed.errorHint).toBe(`Verify the URL: https://www.npmjs.com/package/${bareName}`);
  });

  it.runIf(canRunNpmShimSpawn())('#161: uppercase bare-name miss renders errorHint in plain (non-JSON) output', () => {
    const bareName = 'NONEXISTENT-XYZ-9999';
    resetMarker();
    const res = spawnSync('node', [CLI, 'check', bareName, '--no-scan', '--ci'], {
      encoding: 'utf8',
      timeout: 30_000,
      env: shimEnv(),
    });

    expectShimServedPack(bareName);
    expect(res.status).toBe(1);
    const stderr = res.stderr || '';
    expect(stderr).not.toContain('Invalid skill identifier');
    expect(stderr).toContain(`Verify the URL: https://www.npmjs.com/package/${bareName}`);
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

  it.runIf(canRunSpawn())('#195: pip:<missing> --no-scan honors --no-scan (no PyPI request), emits ecosystem:pypi not-found', () => {
    // Closes hackmyagent#195: prior to the fix, `--no-scan` was silently
    // dropped for pip:/pypi: targets — every check pip:<pkg> --no-scan would
    // still hit PyPI for the metadata + tarball download.
    //
    // Two independent halves, neither of them timed (hackmyagent#397):
    //
    //   Routing.  Exit 2 is reachable from exactly one place — the `--no-scan`
    //   + Registry-miss short-circuit. Drop `--no-scan` again and the run
    //   fetches pypi.org/pypi/<name>/json, takes the 404 branch, and exits 1.
    //   So the exit code alone separates fixed from regressed.
    //
    //   No download.  Asserted against the recorded host list rather than a
    //   clock. This also covers a regression the wall clock could not have
    //   caught in principle: a PyPI fetch reintroduced ABOVE the short-circuit
    //   would still exit 2, and on a fast link would still have come in under
    //   five seconds.
    const bareName = 'opena2a-fixture-pypi-nonexistent-xyz-do-not-publish-20260525';
    resetNetMarker();
    const res = spawnSync(
      'node',
      ['--require', NET_RECORDER, CLI, 'check', `pip:${bareName}`, '--no-scan', '--json', '--ci'],
      {
        encoding: 'utf8',
        // Generous on purpose. Duration is no longer part of the assertion, so
        // this is only a hang guard — a slow Registry must not fail the test.
        timeout: 30_000,
        env: netEnv(),
      },
    );

    expect(res.status).toBe(2);

    const hosts = recordedHosts();

    // In-run non-vacuity. `not.toContain` passes trivially against an empty
    // list, so a preload that silently stopped loading — renamed env var, a
    // Node change to `fetch`, a lost `--require` — would read as "no PyPI
    // request" and this gate would quietly stop gating. The Registry lookup
    // runs unconditionally on this path, so its host must be present in the
    // very run whose absence-claim the next two assertions rest on.
    expect(hosts).toContain('api.oa2a.org');

    expect(hosts).not.toContain('pypi.org');
    expect(hosts).not.toContain('files.pythonhosted.org');

    const stdout = (res.stdout || '').trim();
    expect(stdout.length).toBeGreaterThan(0);

    const parsed = JSON.parse(stdout);
    expect(parsed.name).toBe(bareName);
    expect(parsed.found).toBe(false);
    expect(parsed.ecosystem).toBe('pypi');
    expect(typeof parsed.error).toBe('string');
    expect(parsed.error.length).toBeGreaterThan(0);
  });

  it.runIf(canRunSpawn())('#397 control: the recorder does observe the PyPI request the #195 gate rules out', () => {
    // The control for the assertion above. `expect(hosts).not.toContain('pypi.org')`
    // is only meaningful if a pypi.org request WOULD have shown up in that list,
    // and the in-run `api.oa2a.org` check proves the recorder is alive but not
    // that it can see this particular request. This runs the same command with
    // `--no-scan` removed — the one path that fetches PyPI metadata
    // unconditionally — and asserts the host is recorded.
    //
    // Offline-safe, and deliberately so: the recorder logs at the call site
    // before dispatch, so this asserts the request was attempted, not that it
    // succeeded. Nothing here is asserted about the exit code or the output,
    // because the point is only that the instrumentation can see PyPI.
    const bareName = 'opena2a-fixture-pypi-nonexistent-xyz-do-not-publish-20260525';
    resetNetMarker();
    spawnSync(
      'node',
      ['--require', NET_RECORDER, CLI, 'check', `pip:${bareName}`, '--json', '--ci'],
      { encoding: 'utf8', timeout: 30_000, env: netEnv() },
    );

    expect(recordedHosts()).toContain('pypi.org');
  });
});
