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

  it('--json -o under a directory that does not exist still exits 2, with the document on stdout', () => {
    const dir = tmp('hma-866-unwritable-');
    const missing = path.join(dir, 'no-such-dir');
    const out = path.join(dir, 'no-such-output-dir', 'report.json');
    const r = run(['secure', missing, '--json', '-o', out]);
    expect(r.status, r.stderr).toBe(2);
    expect(fs.existsSync(out)).toBe(false);
    const doc = JSON.parse(r.stdout);
    expect(doc.measured).toBe(false);
    expect(doc.exitCode).toBe(2);
    expect(doc.coverage.reason).toBe('target-not-found');
    expect(r.stderr).toContain('Could not write the report');
    expect(r.stderr).not.toContain('Report written to');
  });

  // #880 — RED-ON-BASE (e1fc64b0): the path was escaped, then the system
  // error message repeated it raw, so an ESC in the `-o` path reached the
  // terminal in the second copy.
  it('RED-ON-BASE: an unwritable -o path with a control character reaches stderr escaped in both copies', () => {
    const dir = tmp('hma-880-');
    const missing = path.join(dir, 'no-such-dir');
    const out = path.join(dir, 'no-such-output-dir', 'a\u001b[31mb.json');
    const r = run(['secure', missing, '--json', '-o', out]);
    expect(r.status, r.stderr).toBe(2);
    const line = r.stderr.split('\n').find((l) => l.startsWith('Could not write the report'));
    expect(line, r.stderr).toBeDefined();
    expect(r.stderr).not.toContain('\u001b');
    expect(line!.split('a\\e[31mb.json')).toHaveLength(3);
    expect(JSON.parse(r.stdout).coverage.reason).toBe('target-not-found');
  });

  // #882 — RED-ON-BASE (a67dce41): `--format sarif -o` and `--format html -o`
  // exited 2 with no report file and nothing naming the file, while `--help`
  // said `-o` writes those reports. No not-measured SARIF is written: an
  // upload with no results closes the repository's open alerts, a clean
  // reading from a run that scanned nothing. The file stays absent, stderr
  // says so, and `--help` scopes `-o` to json for a missing target.
  for (const format of ['sarif', 'html']) {
    it(`RED-ON-BASE: --format ${format} -o names the report it did not write and exits 2`, () => {
      const dir = tmp(`hma-882-${format}-`);
      const report = path.join(dir, `report.${format}`);
      const r = run(['secure', path.join(dir, 'no-such-dir'), '--format', format, '-o', report]);
      expect(r.status, r.stderr).toBe(2);
      expect(fs.existsSync(report)).toBe(false);
      expect(r.stdout).toBe('');
      expect(r.stderr).toMatch(/NOT MEASURED — .* does not exist, so nothing was scanned\./);
      expect(r.stderr).toContain(`No report was written to ${report}`);
      expect(r.stderr).toContain('use --format json -o <file>');
      expect(r.stderr).not.toContain('Report written to');
    });
  }

  it('RED-ON-BASE: --help says a missing target writes the -o file only for json', () => {
    const r = run(['secure', '--help']);
    const flat = r.stdout.replace(/\s+/g, ' ');
    expect(flat).toContain('Write the json, sarif, html, asp or asff report to a file instead of stdout (not with text)');
    expect(flat).toContain('a target that does not exist writes the file only for json');
  });

  it('without -o the missing-target stderr names no report', () => {
    const r = run(['secure', path.join(tmp('hma-882-none-'), 'no-such-dir'), '--format', 'sarif']);
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).not.toContain('No report was written');
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
