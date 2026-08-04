// A findings-bearing scan still reports usage telemetry (#297).
//
// Every scan-output branch called `process.exit(1)` when it found something,
// which kills the process before Commander runs `postAction` — and `postAction`
// is where the event fires. Measured on `aef68fd` against a fixture with one
// CRITICAL (a `ghp_` token in `config.json`), with the endpoint pointed at a
// dead port so nothing leaves the machine:
//
//   mode             exit   telemetry events
//   <text>            1      0
//   --json            1      1
//   --format sarif    1      0
//   --format html     1      0
//   --format asff     1      0
//
// So the default human-facing mode reported CLEAN scans only, and any
// "scans run" figure was biased toward the tool finding nothing. `--json` was
// the single mode that worked, because it sets `process.exitCode` and returns.
//
// The exit CODE is asserted alongside the event on purpose. The obvious repair
// — swap `process.exit(1)` for `process.exitCode = 1` — restores the event and
// can silently drop the non-zero status if a later branch returns first, which
// would break every CI pipeline gating on this command while the metric it was
// meant to fix looks healthy.
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(() => {
  // Presence is not freshness. #285's process note: spawn suites gated on
  // `existsSync(dist/cli.js)`, so roughly half of one round's coverage ran
  // against a stale binary and passed. `assertDistFresh` already states that
  // property once for every spawn suite -- the first draft of this file
  // reimplemented it, which is a second copy to drift.
  assertDistFresh();
});

/** A tree that scores one CRITICAL, so every mode takes its findings branch. */
function fixture(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-297-'));
  const target = path.join(dir, 'proj');
  mkdirSync(target);
  writeFileSync(path.join(target, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(
    path.join(target, 'config.json'),
    '{"token":"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}\n',
  );
  return dir;
}

/** Run `secure` in one output mode and report what came back. */
function scan(mode: string[]): { status: number | null; events: number } {
  const base = fixture();
  const run = spawnSync(process.execPath, [CLI, 'secure', path.join(base, 'proj'), ...mode], {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      ...process.env,
      // A sandboxed HOME so the developer's own telemetry config and install id
      // are neither read nor written.
      HOME: path.join(base, 'home'),
      OPENA2A_TELEMETRY_DEBUG: 'print',
      // Discard port. The assertion is that the event was BUILT and posted, not
      // that a server received it — and a test must not emit real telemetry.
      OPENA2A_TELEMETRY_ENDPOINT: 'http://127.0.0.1:9/',
      NO_COLOR: '1',
    },
  });
  const stderr = run.stderr ?? '';
  return {
    status: run.status,
    events: (stderr.match(/\[opena2a:telemetry\]/g) ?? []).length,
  };
}

describe('telemetry survives a findings-bearing scan (#297)', () => {
  it.each([
    ['text (default)', []],
    ['--json', ['--json']],
    ['sarif', ['--format', 'sarif']],
    ['html', ['--format', 'html']],
    ['asff', ['--format', 'asff']],
  ])('%s emits exactly one event and still exits 1', (_label, mode) => {
    const { status, events } = scan(mode as string[]);
    expect(status, 'a scan with a CRITICAL finding must exit 1').toBe(1);
    expect(events, 'exactly one command event, not zero and not two').toBe(1);
  }, 180_000);
});

describe('the instrument is real (#297)', () => {
  // The measurement above is worthless if the debug switch is a no-op — an
  // earlier pass at this issue "measured" telemetry by grepping for the word
  // `telemetry` in JSON output and read the result as a signal. So the switch
  // is shown to be the thing producing the line: with it off, nothing.
  it('prints nothing without OPENA2A_TELEMETRY_DEBUG', () => {
    const base = fixture();
    const run = spawnSync(process.execPath, [CLI, 'secure', path.join(base, 'proj')], {
      encoding: 'utf8',
      timeout: 120_000,
      env: {
        ...process.env,
        HOME: path.join(base, 'home'),
        OPENA2A_TELEMETRY_ENDPOINT: 'http://127.0.0.1:9/',
        OPENA2A_TELEMETRY_DEBUG: '',
        NO_COLOR: '1',
      },
    });
    expect(run.stderr ?? '').not.toContain('[opena2a:telemetry]');
  }, 180_000);

  it('spawned the CLI at all', () => {
    // Non-vacuity: `events === 0` also happens when the binary cannot start.
    const out = execFileSync(process.execPath, [CLI, '--version'], { encoding: 'utf8' });
    expect(out.trim()).toMatch(/\d+\.\d+\.\d+/);
  });
});
