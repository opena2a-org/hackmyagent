/**
 * #605 — `--json` is the deprecated alias of `--format json`; given together
 * with a DIFFERENT format the two contradict, and the contradiction used to
 * resolve silently in --json's favor: `secure --ci --json --format sarif`
 * printed the json report at exit 0 with nothing to say the requested
 * format was discarded. Now both commands that carry the two flags (secure
 * and attack — `eval` has --format but no --json; scan-soul has --json but
 * no --format) refuse the contradiction where their other format errors are
 * raised, pre-scan.
 *
 * The check keys on Commander's option-value SOURCE, because --format has a
 * 'text' DEFAULT: bare `--json` sees format='text' from the default and
 * must stay untouched, and the redundant agreement (`--json --format
 * json`) has nothing to resolve and stays allowed — a refusal there would
 * break scripts that spell the same thing twice.
 *
 * RED-ON-BASE: contradiction cells exit 0/ran on 203356c; the attack
 * `--format ''` cell documents the `?? 'text'` fix (#632's truthiness
 * class, previously fixed on secure only).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-605-home-')) },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const dir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hma-605-'));

describe('#605 --json contradicting --format refuses, pre-scan', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: secure --json --format sarif refuses at exit 1, naming the alias, with no report on stdout', () => {
    const r = run(['secure', dir(), '--json', '--format', 'sarif', '--no-machine-posture']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/deprecated alias.*--format sarif.*Drop one/s);
    expect(r.stdout).not.toContain('{');
  });

  it('secure --json --format json is the redundant agreement and still runs', () => {
    const r = run(['secure', dir(), '--json', '--format', 'json', '--no-machine-posture']);
    expect(r.stderr).not.toMatch(/deprecated alias|contradicts/);
    // An empty temp dir settles unmeasured; the point is the run HAPPENED
    // and produced the json document the flags agree on.
    expect(() => JSON.parse(r.stdout.slice(r.stdout.indexOf('{'), r.stdout.lastIndexOf('}') + 1))).not.toThrow();
  });

  it("bare --json is untouched — Commander's 'text' default is not an explicit --format", () => {
    const r = run(['secure', dir(), '--json', '--no-machine-posture']);
    expect(r.stderr).not.toMatch(/deprecated alias|contradicts/);
    expect(() => JSON.parse(r.stdout.slice(r.stdout.indexOf('{'), r.stdout.lastIndexOf('}') + 1))).not.toThrow();
  });

  it('RED-ON-BASE: attack --json --format sarif refuses before any connection', () => {
    // The refusal fires at flag validation, so the dead target is never
    // contacted — the cell completes fast on a port nothing listens on.
    const r = run(['attack', 'http://127.0.0.1:9', '--json', '--format', 'sarif']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/deprecated alias.*--format sarif.*Drop one/s);
  });

  it("RED-ON-BASE: attack --format '' reaches the invalid-format refusal instead of falling to text", () => {
    const r = run(['attack', 'http://127.0.0.1:9', '--format', '']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Invalid format ''/);
  });
});
