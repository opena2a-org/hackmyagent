/**
 * #481 — `secure` on a target that does not exist keeps the same contract as
 * `check`: exit 2 ("not measured"), and a JSON document under `--json`.
 *
 * RED-ON-BASE: on 044301c5 `secure --json <missing>` wrote NOTHING to stdout
 * (the error line went to stderr, so a CI step's `JSON.parse` on the report
 * file threw) and exited 1, which the help defines as "measured, and a
 * critical/high issue was found". `check <missing>` already exited 2 with
 * `coverage.measured: false`.
 *
 * The site is still the exit-surface ratchet's S002, a registered pre-work
 * refusal that emits no telemetry event until #525; that half is pinned in
 * `__tests__/cli/exit-event-emission.test.ts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const cleanups: string[] = [];
afterAll(() => {
  for (const d of cleanups) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

function tmp(prefix: string): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanups.push(d);
  return d;
}

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tmp('hma-481-home-') },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('#481 secure on a missing target is unmeasured, exit 2', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: --json emits one parseable document with coverage.measured false', () => {
    const missing = path.join(tmp('hma-481-'), 'no-such-dir');
    const r = run(['secure', missing, '--json']);
    expect(r.status, r.stderr).toBe(2);
    const doc = JSON.parse(r.stdout);
    expect(doc.measured).toBe(false);
    expect(doc.exitCode).toBe(2);
    expect(doc.verdict).toBeNull();
    expect(doc.target).toBe(missing);
    expect(doc.coverage.measured).toBe(false);
    expect(doc.coverage.reason).toBe('target-not-found');
  });

  it('--format json is the same channel as --json', () => {
    const missing = path.join(tmp('hma-481-fmt-'), 'no-such-dir');
    const r = run(['secure', missing, '--format', 'json']);
    expect(r.status, r.stderr).toBe(2);
    expect(JSON.parse(r.stdout).coverage.reason).toBe('target-not-found');
  });

  // #866 — RED-ON-BASE (f561c998): with `-o` the document still went to
  // stdout and the report file was never created, while the measured arm
  // writes the file. A CI step that parses the report file found nothing.
  it('RED-ON-BASE: --json -o writes the document to the file and still exits 2', () => {
    const dir = tmp('hma-866-');
    const missing = path.join(dir, 'no-such-dir');
    const report = path.join(dir, 'report.json');
    const r = run(['secure', missing, '--json', '-o', report]);
    expect(r.status, r.stderr).toBe(2);
    expect(fs.existsSync(report), r.stdout).toBe(true);
    const doc = JSON.parse(fs.readFileSync(report, 'utf8'));
    expect(doc.measured).toBe(false);
    expect(doc.exitCode).toBe(2);
    expect(doc.verdict).toBeNull();
    expect(doc.target).toBe(missing);
    expect(doc.coverage.reason).toBe('target-not-found');
    expect(r.stdout).not.toContain('"target-not-found"');
    expect(r.stderr).toContain(`Report written to ${report}`);
  });

  it('--format json -o writes the same document to the file', () => {
    const dir = tmp('hma-866-fmt-');
    const report = path.join(dir, 'report.json');
    const r = run(['secure', path.join(dir, 'no-such-dir'), '--format', 'json', '-o', report]);
    expect(r.status, r.stderr).toBe(2);
    expect(JSON.parse(fs.readFileSync(report, 'utf8')).coverage.reason).toBe('target-not-found');
  });

  it('RED-ON-BASE: text mode exits 2 and says nothing was measured', () => {
    const missing = path.join(tmp('hma-481-txt-'), 'no-such-dir');
    const r = run(['secure', missing]);
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).toMatch(/NOT MEASURED — .* does not exist, so nothing was scanned\./);
    expect(r.stderr).toContain('Verify: ls -ld');
  });

  it('secure and check agree on the exit code for the same missing target', () => {
    const missing = path.join(tmp('hma-481-agree-'), 'no-such-dir');
    const s = run(['secure', missing]);
    const c = run(['check', missing, '--offline']);
    expect(s.status).toBe(c.status);
  });
});
