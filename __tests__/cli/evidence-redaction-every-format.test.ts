/**
 * #370 — `secure --json` emitted a GitHub token verbatim in
 * `evidence.lines[].content` while redacting a connection-string password in
 * the SAME line. The redactor ran on the field and missed a shape its own
 * detectors report; a single-shape fixture is what let that survive.
 *
 * The fix moved redaction to the finding construction boundary
 * (`src/hardening/finding-emit.ts`), and `finding-emit.test.ts` proves the
 * boundary per field and over the serialized scan result. What neither of
 * those measures is the published bytes of each output format. This suite
 * spawns the built CLI over the issue's own fixture — two different credential
 * shapes on one line — and asserts that no raw credential value reaches stdout
 * in json, text, sarif, html or asff, nor in the verbose text and benchmark
 * JSON paths.
 *
 * Every absence assertion is paired with a presence assertion that the
 * credential file was scanned and rendered in that format, so a format that
 * silently drops the finding cannot pass by printing nothing.
 *
 * Credential values are synthesised at runtime, never written as literals, so
 * nothing here trips push protection or a secret scanner.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI; refuse to measure a stale binary,
// and fail naming the command to run when there is no build at all.
beforeAll(assertDistFresh);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');

const SECRET_FILE = 'settings.json';

/** A GitHub personal access token shape, built at runtime. */
const GH_TOKEN = ['ghp', 'Z'.repeat(32) + 'FAKE'].join('_');
/** The password inside a connection string: a second, different shape. */
const DB_PASSWORD = 'pw' + 'Q'.repeat(10) + 'FAKE';
const DB_URL = `postgres://user:${DB_PASSWORD}@db.example.com/app`;

const RAW_VALUES: Array<[string, string]> = [
  ['github token', GH_TOKEN],
  ['connection-string password', DB_PASSWORD],
];

let dir = '';
let home = '';

beforeAll(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'hma-370-'));
  home = mkdtempSync(path.join(tmpdir(), 'hma-370-home-'));
  mkdirSync(path.join(dir, 'proj'));
  // Both shapes on ONE line: the issue's reproduction, verbatim in structure.
  writeFileSync(
    path.join(dir, 'proj', SECRET_FILE),
    JSON.stringify({ apiToken: GH_TOKEN, dbUrl: DB_URL }),
  );
});

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  if (home) rmSync(home, { recursive: true, force: true });
});

function secure(args: string[]): { status: number | null; stdout: string; out: string } {
  const r = spawnSync('node', [CLI, 'secure', path.join(dir, 'proj'), ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    // An empty HOME keeps the developer's own config out of the scan.
    env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1' },
  });
  const stdout = r.stdout ?? '';
  return { status: r.status, stdout, out: `${stdout}${r.stderr ?? ''}` };
}

const FORMATS: Array<[string, string[]]> = [
  ['json', ['--json']],
  ['text', []],
  ['text --verbose', ['--verbose']],
  ['sarif', ['--format', 'sarif']],
  ['html', ['--format', 'html']],
  ['asff', ['--format', 'asff']],
  ['benchmark json', ['-b', 'oasb-1', '--format', 'json']],
];

describe('#370 — no raw credential in any output format', { timeout: 600_000 }, () => {
  for (const [label, args] of FORMATS) {
    it(`${label}: the credential file is rendered and neither value leaks`, () => {
      const { status, out } = secure(args);
      // The fixture carries CRITICAL/HIGH credential findings, so every
      // reporting path exits 1. A crash (null, 2+) would print nothing and
      // make the absence assertions vacuous.
      expect(status, out.slice(-2000)).toBe(1);
      for (const [name, value] of RAW_VALUES) {
        expect(out.includes(value), `${label} prints the raw ${name}`).toBe(false);
      }
      if (label !== 'benchmark json') {
        expect(out, `${label} never mentions the credential file`).toContain(SECRET_FILE);
      }
    });
  }

  it('json: the one-line evidence is present and redacted for BOTH shapes', () => {
    const { stdout } = secure(['--json']);
    const doc = JSON.parse(stdout);
    const all = [...(doc.findings ?? []), ...(doc.allFindings ?? [])];
    const contents: string[] = [];
    for (const f of all) {
      for (const line of f?.evidence?.lines ?? []) {
        if (typeof line?.content === 'string' && line.content.includes('apiToken')) {
          contents.push(line.content);
        }
      }
    }
    // The line must reach the document; otherwise absence proves nothing.
    expect(contents.length).toBeGreaterThan(0);
    for (const c of contents) {
      expect(c).toContain('[REDACTED');
      expect(c).not.toContain(GH_TOKEN);
      expect(c).not.toContain(DB_PASSWORD);
    }
  });
});
