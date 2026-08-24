/**
 * #494 / #512 — `--fail-below` settles once, above every output channel, and
 * only ever RAISES the exit code.
 *
 * Two directions, both red on the build before the fix:
 *
 * - #494: under `--format sarif|html|asff` the flag was never read — the check
 *   was a per-channel copy on text and json only — so a below-threshold score
 *   exited 0 with nothing on stderr. SARIF is the format CI uploads.
 * - #512: over a tree holding an input the run could not read, `secure`
 *   settles a floor of exit 2 (#438). The per-channel copies then ASSIGNED
 *   exit 1 over it, so adding a stricter flag turned "I could not measure
 *   this" into "I measured it and it failed".
 *
 * Every threshold here is pinned from both sides. Each fixture's score is
 * measured first through `--format json`, and the assertions use one
 * threshold above it (triggering) and one at it (not triggering). A fixture
 * that stopped scoring what this file assumes would otherwise leave every
 * exit-code assertion green while measuring nothing.
 *
 * `chmod 000` does not deny root, so the #512 cases probe for real
 * unreadability and skip with a warning when they cannot get it.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

/** Measured, and the result is one the command promises to pass. */
const EXIT_PASS = 0;
/** Measured, and the result is one the command promises to fail on. */
const EXIT_FAIL = 1;
/** The run did not examine everything it found. */
const EXIT_UNMEASURED = 2;

/**
 * Every renderer the non-benchmark `secure` has. `--format asp` is also
 * accepted by the validator but is a benchmark-only renderer; outside `-b` it
 * falls through to the text arm (#563), so it would exercise `text` twice.
 */
const FORMATS = ['text', 'json', 'sarif', 'html', 'asff'] as const;
type Format = (typeof FORMATS)[number];

let root: string;
/** Files whose modes must be restored before the tree can be removed. */
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
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

function withFormat(format: Format, args: string[]): string[] {
  return format === 'text' ? args : [...args, '--format', format];
}

/** The score the CLI itself reports for `dir`, read off the JSON channel. */
function scoreOf(dir: string): number {
  const res = run(['secure', dir, '--format', 'json']);
  const body = JSON.parse(res.stdout.slice(res.stdout.indexOf('{')));
  expect(typeof body.score, 'the json channel must report a numeric score').toBe('number');
  return body.score as number;
}

/**
 * A tree that scores below 100 for a reason that is neither critical nor high,
 * so nothing but the threshold can move its exit code off 0: `package.json`,
 * two benign sources and an incomplete `.gitignore` — the shape of #494's own
 * reproduction.
 */
function cleanTree(name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fb-probe", "version": "1.0.0", "private": true }\n');
  fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
  fs.writeFileSync(path.join(dir, 'src', 'greet.js'), 'module.exports = (n) => `hi ${n}`;\n');
  fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n');
  return dir;
}

/** Make a path unreadable and PROVE it. Returns false when the OS declined. */
function makeUnreadable(file: string): boolean {
  fs.chmodSync(file, 0o000);
  restore.push(file);
  try {
    fs.readFileSync(file);
    return false; // root, or a filesystem without permission support
  } catch {
    return true;
  }
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-494-512-'));
});

afterAll(() => {
  // Restore modes here rather than in a try/finally in a test body: a vitest
  // timeout skips a `finally`, and an unreadable file blocks the rmSync.
  for (const p of restore) {
    try { fs.chmodSync(p, 0o644); } catch { /* already gone */ }
  }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#494 --fail-below is honoured on every output channel', () => {
  let dir: string;
  let score: number;

  beforeAll(() => {
    dir = cleanTree('clean');
    score = scoreOf(dir);
  });

  it('the fixture scores strictly between 0 and 100 and exits 0 with no threshold', () => {
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(100);
    // Nothing but `--fail-below` can move this tree off exit 0.
    expect(run(['secure', dir]).status).toBe(EXIT_PASS);
  });

  for (const format of FORMATS) {
    it(`${format}: a score below the threshold exits 1 and says so on stderr`, () => {
      const res = run(withFormat(format, ['secure', dir, '--fail-below', String(score + 1)]));
      expect(res.status).toBe(EXIT_FAIL);
      expect(res.stderr).toContain(`Score ${score} is below threshold ${score + 1}`);
    });

    it(`${format}: a score at the threshold exits 0 and says nothing`, () => {
      const res = run(withFormat(format, ['secure', dir, '--fail-below', String(score)]));
      expect(res.status).toBe(EXIT_PASS);
      expect(res.stderr).not.toContain('is below threshold');
    });
  }

  it('the breach is reported once, not once per channel copy', () => {
    const res = run(['secure', dir, '--format', 'sarif', '--fail-below', String(score + 1)]);
    expect(res.stderr.split('is below threshold').length - 1).toBe(1);
  });

  it('text: the reason follows the report, where a reader at a terminal expects it', () => {
    // Settling the exit code above the channels must not move the sentence
    // that explains it to the top of a 45-line run. Separate stdout/stderr
    // pipes cannot see that: stderr holds only progress lines and the reason
    // on EITHER placement, so "last on stderr" passes vacuously. Both streams
    // are written through one file descriptor instead, which records the
    // interleaving a terminal shows.
    const capture = path.join(root, 'text-order.log');
    const fd = fs.openSync(capture, 'w');
    let status: number | null;
    try {
      status = spawnSync(process.execPath, [CLI, 'secure', dir, '--fail-below', String(score + 1)], {
        stdio: ['ignore', fd, fd],
        timeout: 240_000,
        env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
      }).status;
    } finally {
      fs.closeSync(fd);
    }
    const merged = fs.readFileSync(capture, 'utf-8');
    expect(status).toBe(EXIT_FAIL);
    // The report's last body line is the `All commands:` hint; the version
    // footer is printed from a `process.on('exit')` handler and is always the
    // final line, before and after this change. Measured on published 0.30.0
    // (its text-arm threshold block is unchanged through 0.32.0): reason at
    // line 44 of 45, footer at 45 — and that is the order pinned here. `indexOf` finds the FIRST occurrence, so a second copy
    // emitted at the settlement point (line 5) fails this too.
    const lastReportLine = merged.indexOf('All commands:');
    const footer = merged.indexOf('Scanned with hackmyagent');
    const reason = merged.indexOf('is below threshold');
    expect(lastReportLine, 'the report body must be in the capture').toBeGreaterThan(-1);
    expect(footer, 'the exit footer must be in the capture').toBeGreaterThan(-1);
    expect(reason, 'the reason must be in the capture').toBeGreaterThan(-1);
    expect(reason).toBeGreaterThan(lastReportLine);
    expect(reason).toBeLessThan(footer);
  });

  it('the report still reaches stdout when the threshold trips (sarif stays parseable)', () => {
    const res = run(['secure', dir, '--format', 'sarif', '--fail-below', String(score + 1)]);
    const sarif = JSON.parse(res.stdout.slice(res.stdout.indexOf('{')));
    expect(sarif.version).toBe('2.1.0');
  });
});

describe('#512 --fail-below never lowers the exit-2 unmeasured floor', () => {
  let dir: string;
  let unreadable = false;
  let score: number;

  beforeAll(() => {
    dir = cleanTree('unread');
    unreadable = makeUnreadable(path.join(dir, 'src', 'greet.js'));
    if (unreadable) score = scoreOf(dir);
  });

  /** True when the environment could not give us a genuinely unreadable file. */
  function cannotProbe(): boolean {
    if (!unreadable) console.warn('skipped: this process can read a mode-000 file (running as root?)');
    return !unreadable;
  }

  it('the fixture is unmeasured with no threshold, and still reports a score', () => {
    if (cannotProbe()) return;
    expect(run(['secure', dir]).status).toBe(EXIT_UNMEASURED);
    expect(score).toBeLessThan(100);
  });

  for (const format of FORMATS) {
    it(`${format}: a triggering threshold still exits 2, because a stricter flag cannot weaken the signal`, () => {
      if (cannotProbe()) return;
      const res = run(withFormat(format, ['secure', dir, '--fail-below', String(score + 1)]));
      expect(res.status).toBe(EXIT_UNMEASURED);
      // The breach is still reported; only the exit code is held at the floor.
      expect(res.stderr).toContain(`Score ${score} is below threshold ${score + 1}`);
    });
  }

  it('a non-triggering threshold leaves the floor alone', () => {
    if (cannotProbe()) return;
    expect(run(['secure', dir, '--fail-below', String(score)]).status).toBe(EXIT_UNMEASURED);
  });

  it('CONTROL: the same tree, once readable, exits 1 on a triggering threshold', () => {
    if (cannotProbe()) return;
    fs.chmodSync(path.join(dir, 'src', 'greet.js'), 0o644);
    const readable = scoreOf(dir);
    expect(readable).toBeLessThan(100);
    expect(run(['secure', dir, '--fail-below', String(readable + 1)]).status).toBe(EXIT_FAIL);
  });
});
