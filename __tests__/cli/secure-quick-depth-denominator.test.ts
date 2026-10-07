/**
 * #507 — `secure --scan-depth quick` prints its score with the denominator it
 * was measured over.
 *
 * Measured before the change on a clean, fully readable tree (`src/util.js`, a
 * populated `.gitignore`, a `package.json` with no lock file):
 *
 *   --scan-depth quick     exit 0  `Security ━━━━ 98/100`  6 of 63 check groups ran
 *   --scan-depth standard  exit 0  `Security ━━━━ 93/100`  63 of 63 check groups ran
 *
 * The quick headline was the same line, at the same width, as the standard
 * one, and scored higher because a group it skipped is the one that finds the
 * missing lock file. Quick keeps its exit 0 (ruled 2026-08-11: a user passing
 * `--scan-depth quick` consented to the depth); what this pins is that the
 * number says what it is over, and that the score itself does not move.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');

let root: string;
let tree: string;
let home: string;

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      // One HOME under `root`, so `afterAll` removes it with the tree (#885:
      // a fresh `mkdtempSync` per spawn left one directory behind per run).
      HOME: home,
    },
  });
  const stdout = (res.stdout ?? '').replace(/\x1b\[[0-9;]*m/g, '');
  return { status: res.status, stdout };
}

function scoreLine(out: string): string {
  const line = out.split('\n').find((l) => /^\s*Security\s.*\d+\/100/.test(l));
  if (!line) throw new Error(`no score line in output:\n${out}`);
  return line;
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-507-'));
  tree = path.join(root, 't');
  home = path.join(root, 'home');
  fs.mkdirSync(home);
  fs.mkdirSync(path.join(tree, 'src'), { recursive: true });
  fs.writeFileSync(path.join(tree, 'src', 'util.js'), 'module.exports = function add(a, b) { return a + b; };\n');
  fs.writeFileSync(path.join(tree, '.gitignore'), 'node_modules/\n.env\n*.log\n');
  fs.writeFileSync(path.join(tree, 'package.json'), '{\n  "name": "t",\n  "version": "1.0.0",\n  "private": true\n}\n');
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#507 a quick-depth score names its denominator', { timeout: 300_000 }, () => {
  it('quick: the score line carries the check-group ratio the Checks line reports', () => {
    const res = run(['secure', tree, '--scan-depth', 'quick']);
    // Settled, and not this change's to move.
    expect(res.status).toBe(0);
    const line = scoreLine(res.stdout);
    const m = /over (\d+) of (\d+) check groups — scan depth quick/.exec(line);
    expect(m, `score line has no denominator: ${line}`).not.toBeNull();
    const [ran, registered] = [Number(m![1]), Number(m![2])];
    expect(ran).toBeLessThan(registered);
    // One tally, two lines: the score-line ratio is the Checks-line ratio.
    expect(res.stdout).toContain(`${ran} of ${registered} check groups ran`);
    // And the reader is told how to get the number quick did not measure, with
    // a command that runs when pasted: the CLI name, not a bare `secure` (#885).
    expect(res.stdout).toMatch(/Run `hackmyagent secure .+` for the standard-depth score\./);
    // The semantic layer ran, so the score line does not say it was off.
    expect(line).not.toContain('semantic layer off');
  }, 240_000);

  it('quick --static-only: the score line says the semantic layer is off (#885)', () => {
    const res = run(['secure', tree, '--scan-depth', 'quick', '--static-only']);
    const line = scoreLine(res.stdout);
    expect(line).toMatch(/over \d+ of \d+ check groups, semantic layer off — scan depth quick/);
    expect(res.stdout).toContain('0 semantic');
  }, 240_000);

  it('quick: the score is unchanged — the denominator is a disclosure, not a deduction', () => {
    const text = run(['secure', tree, '--scan-depth', 'quick']);
    const printed = Number(/(\d+)\/100/.exec(scoreLine(text.stdout))![1]);
    const json = run(['secure', tree, '--scan-depth', 'quick', '--format', 'json']);
    const body = JSON.parse(json.stdout.slice(json.stdout.indexOf('{')));
    expect(printed).toBe(body.score);
    expect(json.status).toBe(text.status);
  }, 240_000);

  // This control cannot detect a lost `scanDepth !== 'quick'` condition on its
  // own: a standard run completes every registered check group, so the
  // `ran >= registered` guard returns first either way, and this fixture has
  // no non-quick run that leaves a group incomplete. The depth condition is carried
  // by the unit test (`__tests__/ui/scan-depth-disclosure.test.ts`, the
  // standard/deep/undefined cases with 6 groups ran), which fails without it.
  it('CONTROL standard: no quick-depth denominator on a run that did not narrow', () => {
    const res = run(['secure', tree, '--scan-depth', 'standard']);
    expect(res.status).toBe(0);
    expect(scoreLine(res.stdout)).not.toContain('scan depth quick');
    expect(res.stdout).not.toContain('for the standard-depth score');
  }, 240_000);
});
