// #761 — `check @publisher/skill` (the placeholder in `check --help` and the
// README), or any scoped name npm does not have, fell through to the
// skill-identifier lookup and printed `MEDIUM RISK` at exit 0. That lookup
// fetches nothing about the skill: it reads the publisher's DNS TXT record and
// a local blocklist. A scoped miss is now not measured: the npm not-found
// block with its verify URL, exit 2, and the publisher record.
//
// These spawn the built CLI with `--offline`, which skips the Registry and the
// DNS lookup, and a PATH-injected `npm` shim that emits npm's real E404 for
// `pack` (the same shim check-not-found-json.test.ts uses, hackmyagent#203),
// so no run touches the network.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI.
beforeAll(assertDistFreshIfPresent);

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');

function resolveRealNpm(): string | undefined {
  const res = spawnSync('sh', ['-c', 'command -v npm'], { encoding: 'utf8' });
  const found = (res.stdout || '').trim();
  return found.length > 0 ? found : undefined;
}

function canRunNpmShimSpawn(): boolean {
  return process.platform !== 'win32' && existsSync(CLI) && resolveRealNpm() !== undefined;
}

let stubDir: string | undefined;
let markerFile: string | undefined;

beforeAll(() => {
  if (!canRunNpmShimSpawn()) return;
  stubDir = mkdtempSync(join(tmpdir(), 'hma-npm-shim-761-'));
  markerFile = join(stubDir, 'invocations.log');
  writeFileSync(
    join(stubDir, 'npm'),
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
exec ${resolveRealNpm()} "$@"
`,
    { mode: 0o755 },
  );
});

afterAll(() => {
  if (stubDir) rmSync(stubDir, { recursive: true, force: true });
});

function runCheck(target: string, extra: string[]) {
  writeFileSync(markerFile!, '');
  const res = spawnSync('node', [CLI, 'check', target, '--offline', '--ci', ...extra], {
    encoding: 'utf8',
    timeout: 30_000,
    env: {
      ...process.env,
      PATH: `${stubDir}${delimiter}${process.env.PATH ?? ''}`,
      HMA_TEST_NPM_SHIM_MARKER: markerFile!,
    },
  });
  // Non-vacuity: the shim, not the real npm, answered the download.
  expect(readFileSync(markerFile!, 'utf8')).toContain(`pack ${target}`);
  return res;
}

describe('check on a scoped npm miss is not measured (#761)', { timeout: 60_000 }, () => {
  const scopedName = '@opena2a-fixture-nonexistent-761/skill-do-not-publish';
  const verifyHint = `Verify the URL: https://www.npmjs.com/package/${scopedName}`;

  it.runIf(canRunNpmShimSpawn())('--json: not-found shape, exit 2, no risk band, publisher record kept', () => {
    const res = runCheck(scopedName, ['--json']);

    expect(res.status).toBe(2);
    const parsed = JSON.parse((res.stdout || '').trim());
    expect(parsed.name).toBe(scopedName);
    expect(parsed.found).toBe(false);
    expect(parsed.ecosystem).toBe('npm');
    expect(parsed.errorHint).toBe(verifyHint);
    expect(parsed.coverage.measured).toBe(false);
    expect(parsed.coverage.reason).toBe('target-not-found');
    expect(parsed.risk).toBeUndefined();
    expect(parsed.publisher.name).toBe('opena2a-fixture-nonexistent-761');
    expect(parsed.publisher.verified).toBe(false);
  });

  it.runIf(canRunNpmShimSpawn())('plain output: verify URL and publisher record, no risk verdict, exit 2', () => {
    const res = runCheck(scopedName, []);

    expect(res.status).toBe(2);
    expect(res.stderr || '').toContain(verifyHint);
    const stdout = res.stdout || '';
    expect(stdout).toContain('Publisher: @opena2a-fixture-nonexistent-761');
    expect(stdout).not.toMatch(/\b(LOW|MEDIUM|HIGH|CRITICAL) RISK\b/);
  });

  it.runIf(canRunNpmShimSpawn())('control: a blocklisted identifier still reports CRITICAL and exits 1', () => {
    const res = runCheck('@malicious/bad-skill', []);

    expect(res.status).toBe(1);
    expect(res.stdout || '').toContain('CRITICAL RISK');
  });
});
