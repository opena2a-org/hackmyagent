/**
 * #514 (disclosure half) — a benchmark run that exits 2 for an input it could
 * not read must say so beside the rating.
 *
 * Before: `generateBenchmarkReport` maps findings through control `checkIds`,
 * and `SCAN-UNREAD-001` belongs to no control, so the one finding explaining
 * the exit code vanished from every benchmark channel — the output printed
 * `Rating: ...` and nothing else while `$?` was 2.
 *
 * This pins the DISCLOSURE only. What a rating may claim over an unread input
 * is the #513 design question, deferred with its own record; the rating and
 * the exit codes here are asserted only for direction-agreement (#514's rule:
 * exit and verdict must not point opposite ways silently).
 *
 * `chmod 000` does not deny root, so the unread cases prove unreadability
 * first and skip with a warning when they cannot get it.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

let root: string;
const restore: string[] = [];

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
    },
  });
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}`, stdout: res.stdout ?? '' };
}

function tree(name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx514", "version": "1.0.0", "private": true }\n');
  fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
  fs.writeFileSync(path.join(dir, 'src', 'greet.js'), 'module.exports = (n) => `hi ${n}`;\n');
  return dir;
}

function makeUnreadable(file: string): boolean {
  fs.chmodSync(file, 0o000);
  restore.push(file);
  try {
    fs.readFileSync(file);
    return false;
  } catch {
    return true;
  }
}

let unreadable = false;
function cannotProbe(): boolean {
  if (!unreadable) console.warn('skipped: this process can read a mode-000 file (running as root?)');
  return !unreadable;
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-514-'));
  const probe = path.join(root, 'probe');
  fs.writeFileSync(probe, 'x');
  unreadable = makeUnreadable(probe);
});

afterAll(() => {
  for (const p of restore) {
    try { fs.chmodSync(p, 0o644); } catch { /* already gone */ }
  }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#514 the benchmark arms disclose what the run could not read', () => {
  it('CONTROL: a fully readable tree prints no unread disclosure and carries count 0 in json', () => {
    const dir = tree('clean');
    const text = run(['secure', dir, '-b', 'oasb-1', '-l', 'L1', '--no-machine-posture']);
    expect(text.out).not.toContain('Unread inputs:');
    const json = run(['secure', dir, '-b', 'oasb-1', '-l', 'L1', '--no-machine-posture', '--format', 'json']);
    const body = JSON.parse(json.stdout.slice(json.stdout.indexOf('{')));
    expect(body.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
  });

  it('text: -b oasb-1 names the unread input and frames compliance as an upper bound', () => {
    if (cannotProbe()) return;
    const dir = tree('mixed');
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const res = run(['secure', dir, '-b', 'oasb-1', '-l', 'L1', '--no-machine-posture']);
    expect(res.out).toContain('Unread inputs: 1');
    expect(res.out).toContain('upper bound');
    expect(res.out).toContain('src/greet.js');
    // Direction agreement (#514): the run must not read as complete while the
    // exit code says it was not. The disclosure IS the agreement; the exit
    // code itself is the floor's and is asserted non-zero only.
    expect(res.status).not.toBe(0);
  });

  it('json: -b oasb-1 carries the record beside the rating', () => {
    if (cannotProbe()) return;
    const dir = tree('mixed-json');
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const res = run(['secure', dir, '-b', 'oasb-1', '-l', 'L1', '--no-machine-posture', '--format', 'json']);
    const body = JSON.parse(res.stdout.slice(res.stdout.indexOf('{')));
    expect(body.rating).toBeDefined();
    expect(body.unreadableInputs.count).toBe(1);
    expect(body.unreadableInputs.codes.EACCES).toBe(1);
    expect(res.status).not.toBe(0);
  });

  it('text: the -b oasb-2 composite discloses too', () => {
    if (cannotProbe()) return;
    const dir = tree('composite');
    makeUnreadable(path.join(dir, 'src', 'greet.js'));
    const res = run(['secure', dir, '-b', 'oasb-2', '--no-machine-posture']);
    expect(res.out).toContain('Unread inputs: 1');
    expect(res.out).toContain('src/greet.js');
  });
});
