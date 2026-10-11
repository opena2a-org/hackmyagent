/**
 * `check <git URL>` says why a clone did not finish when the reason is not
 * the repository: there is no `git` on PATH, or the clone ran out of time.
 *
 * Before this, a run with no git printed `Error scanning URL: spawn git
 * ENOENT` for a URL that ends in `.git` and for a forge URL with no `@`, and
 * `Could not clone repository from "<URL>".` with `Verify the URL is
 * accessible and contains a git repository.` for a forge URL with no `.git`
 * and an `@` before its host, about a URL that was never tried. A clone ended
 * at the time limit printed the failed command line, and for that last kind
 * of URL the `Could not clone` lines. It never printed the `timed out`
 * message and its hint, which were chosen on the word `timeout` in the
 * error's message: the message of a command Node ended at its time limit is
 * the command line, with no such word.
 *
 * Those three readings hold only while the clone has not finished. An error
 * the scan raises after a clone that did finish is not about git or the
 * URL: it prints `Error scanning URL: <message>`, even when it carries
 * `code: 'ENOENT'` or `killed: true` and the URL has a user name and
 * password.
 *
 * A clone git gives up on itself, with `Timeout was reached` in its error,
 * printed the `timed out` lines for every kind of URL here until the URL had
 * a user name or password: then it printed the `Could not clone` lines.
 *
 * Hermetic: with no git, PATH is an empty directory. For the time limit,
 * `git` is a stand-in on PATH that never answers, and
 * __tests__/fixtures/git-time-limit-preload.cjs shortens the 120 s the CLI
 * gives it, so Node's own timer ends it. For a scan that fails, `git` is a
 * stand-in that writes one file where the clone goes and exits 0, and a
 * preload the test writes makes the scan reject. The CLI runs with no proxy
 * variables and with __tests__/helpers/loopback-only.cjs preloaded, so
 * nothing reaches the network. Every credential-bearing URL is assembled at
 * runtime.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

// Every case reads a run of the built CLI, so a checkout that has not built
// fails here, naming the command to run, rather than skipping the suite.
beforeAll(assertDistFresh);

const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');
const GIT_TIME_LIMIT = path.join(__dirname, '..', 'fixtures', 'git-time-limit-preload.cjs');

const USER = 'fakeuser';
const SECRET = ['FAKE', 'secret', '123'].join('');
const REPO = 'gitlab.com/example-org/example-repo';

/** The three kinds of URL `check` hands to git, as typed and as shown. */
const URLS = [
  { kind: 'a forge URL with no `.git` and a user name and password', typed: `https://${USER}:${SECRET}@${REPO}`, shown: `https://${REPO}` },
  { kind: 'a `.git` URL with a user name and password', typed: `https://${USER}:${SECRET}@${REPO}.git`, shown: `https://${REPO}.git` },
  { kind: 'a forge URL with no `.git` and no `@`', typed: `https://${REPO}`, shown: `https://${REPO}` },
] as const;

// Stands in for a git whose clone never answers: it outlasts the shortened
// time limit and is ended by it.
const GIT_NEVER_ANSWERS = `#!/bin/sh
exec sleep 30
`;

// Stands in for a git whose clone succeeds: the last argument is where the
// clone goes, and it gets one file there.
const GIT_CLONES = `#!/bin/sh
for dest; do :; done
mkdir -p "$dest" && printf '# Example repository\\n' > "$dest/README.md"
`;

const BUILT_SCANNER = path.join(__dirname, '..', '..', 'dist', 'hardening', 'scanner.js');

// Makes every scan reject with an error built from $HMA_TEST_SCAN_ERROR: its
// `message`, and each other field set on the error as it is.
const SCAN_REJECTS = `'use strict';
const { HardeningScanner } = require(${JSON.stringify(BUILT_SCANNER)});
const { message, ...fields } = JSON.parse(process.env.HMA_TEST_SCAN_ERROR);
HardeningScanner.prototype.scan = async function scan() {
  throw Object.assign(new Error(message), fields);
};
`;

/**
 * Errors a scan can raise after the clone finished. The last two carry the
 * fields that, on the error of a clone that did not finish, mean there was no
 * git to start and that the time limit ended it. No message holds `128`,
 * `not found` or `timeout`, which choose other lines.
 */
const SCAN_ERRORS = [
  { kind: 'an error with no code', fields: { message: 'injected scan failure after the clone' } },
  { kind: 'an error whose code is ENOENT', fields: { message: "ENOENT: no such file or directory, scandir 'injected-scan-step'", code: 'ENOENT' } },
  { kind: 'an error from a process its time limit ended', fields: { message: 'Command failed: injected-scan-step', killed: true, signal: 'SIGTERM' } },
] as const;

/** Every scan error, for every kind of URL. */
const SCAN_FAILED_CASES = SCAN_ERRORS.flatMap((e) => URLS.map((u) => ({ ...u, error: e.kind, fields: e.fields })));

// Stands in for a git that gives up on the connection itself: it fails at
// once with exit 128 and git's own `Timeout was reached` line, which quotes
// the URL without its user name and password.
const GIT_SAYS_TIMEOUT = `#!/bin/sh
for arg in "$@"; do
  case "$arg" in https://*) rest="\${arg#https://}" ;; esac
done
printf '%s\\n' "fatal: unable to access 'https://\${rest##*@}/': Failed to connect to gitlab.com port 443 after 75002 ms: Timeout was reached" >&2
exit 128
`;

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

let scratch = '';
let emptyBin = '';
let hangBin = '';
let cloneBin = '';
let timeoutWordBin = '';
const noGitRuns: Run[] = [];
const timedOutRuns: Run[] = [];
const scanFailedRuns: Run[] = [];
const timeoutWordRuns: Run[] = [];

function run(label: string, typedUrl: string, extraEnv: NodeJS.ProcessEnv, preloads: string[]): Run {
  const dir = path.join(scratch, label);
  const home = path.join(dir, 'home');
  const opena2aHome = path.join(dir, 'opena2a');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });

  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  // A proxy on loopback would carry a request on to the network.
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, [CLI, 'check', typedUrl], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: opena2aHome,
      NODE_OPTIONS: [env.NODE_OPTIONS, ...preloads.map((file) => `--require "${file}"`)].filter(Boolean).join(' '),
      ...extraEnv,
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

beforeAll(() => {
  // Removed when this file finishes.
  scratch = tempDir('hma-url-clone-');
  emptyBin = path.join(scratch, 'empty-bin');
  hangBin = path.join(scratch, 'hang-bin');
  fs.mkdirSync(emptyBin, { recursive: true });
  fs.mkdirSync(hangBin, { recursive: true });
  fs.writeFileSync(path.join(hangBin, 'git'), GIT_NEVER_ANSWERS, { mode: 0o755 });
  cloneBin = path.join(scratch, 'clone-bin');
  fs.mkdirSync(cloneBin, { recursive: true });
  fs.writeFileSync(path.join(cloneBin, 'git'), GIT_CLONES, { mode: 0o755 });
  const scanRejects = path.join(scratch, 'scan-rejects.cjs');
  fs.writeFileSync(scanRejects, SCAN_REJECTS);
  timeoutWordBin = path.join(scratch, 'timeout-word-bin');
  fs.mkdirSync(timeoutWordBin, { recursive: true });
  fs.writeFileSync(path.join(timeoutWordBin, 'git'), GIT_SAYS_TIMEOUT, { mode: 0o755 });

  URLS.forEach(({ typed }, i) => {
    noGitRuns.push(run(`no-git-${i}`, typed, { PATH: emptyBin }, [LOOPBACK_ONLY]));
  });
  URLS.forEach(({ typed }, i) => {
    timedOutRuns.push(run(
      `timed-out-${i}`,
      typed,
      { PATH: `${hangBin}${path.delimiter}${process.env.PATH ?? ''}`, HMA_TEST_GIT_TIMEOUT_MS: '1000' },
      [LOOPBACK_ONLY, GIT_TIME_LIMIT],
    ));
  });
  SCAN_FAILED_CASES.forEach(({ typed, fields }, i) => {
    scanFailedRuns.push(run(
      `scan-failed-${i}`,
      typed,
      { PATH: `${cloneBin}${path.delimiter}${process.env.PATH ?? ''}`, HMA_TEST_SCAN_ERROR: JSON.stringify(fields) },
      [LOOPBACK_ONLY, scanRejects],
    ));
  });
  URLS.forEach(({ typed }, i) => {
    timeoutWordRuns.push(run(
      `timeout-word-${i}`,
      typed,
      { PATH: `${timeoutWordBin}${path.delimiter}${process.env.PATH ?? ''}` },
      [LOOPBACK_ONLY],
    ));
  });
}, 600_000);

describe('check <git URL> with no git on PATH says that git was not found', () => {
  it.each(URLS.map((u, i) => ({ ...u, i })))('for $kind', ({ shown, i }) => {
    const r = noGitRuns[i];
    const output = r.stdout + r.stderr;
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).toContain(`Error: git was not found on PATH, so "${shown}" was not cloned.`);
    expect(r.stderr).toContain('Install git and run the command again, or download the repository and scan the local path:');
    expect(r.stderr).toMatch(/ check \.\/downloaded-dir\/$/m);
    // Not the lines for a repository that could not be cloned, and not the
    // bare error of the failed start.
    expect(r.stderr).not.toContain('Could not clone repository');
    expect(r.stderr).not.toContain('Verify the URL is accessible');
    expect(r.stderr).not.toContain('ENOENT');
    expect(r.stderr).toContain(`${shown} could not be fetched, so nothing was scanned.`);
    expect(output).not.toContain(SECRET);
    expect(output).not.toContain(USER);
  });

  it('with the same lines for all three, but for the URL they name', () => {
    const [first, ...rest] = URLS.map((u, i) => noGitRuns[i].stderr.split(u.shown).join('<URL>').replace(/Cloning .*\n/, ''));
    expect(first).toContain('git was not found on PATH');
    for (const other of rest) expect(other).toBe(first);
  });
});

describe('check <git URL> whose clone is ended at the time limit says that it timed out', () => {
  it.each(URLS.map((u, i) => ({ ...u, i })))('for $kind', ({ shown, i }) => {
    const r = timedOutRuns[i];
    const output = r.stdout + r.stderr;
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).toContain(`Error: Fetching "${shown}" timed out. The target may be too large.`);
    expect(r.stderr).toContain('Try downloading manually and scanning the local path:');
    expect(r.stderr).toMatch(/ check \.\/downloaded-dir\/$/m);
    // Not the lines for a repository that could not be cloned, and not the
    // failed command line.
    expect(r.stderr).not.toContain('Could not clone repository');
    expect(r.stderr).not.toContain('Command failed');
    expect(r.stderr).not.toContain('git was not found');
    expect(output).not.toContain(SECRET);
    expect(output).not.toContain(USER);
  });
});

describe('check <git URL> whose clone finished and whose scan then failed prints the scan error', () => {
  it.each(SCAN_FAILED_CASES.map((c, i) => ({ ...c, i })))('for $error, on $kind', ({ shown, fields, i }) => {
    const r = scanFailedRuns[i];
    const output = r.stdout + r.stderr;
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).toContain(`Error scanning URL: ${fields.message}`);
    expect(r.stderr).toContain(`${shown} was fetched but could not be analyzed, so no verdict was measured.`);
    // Not the lines for a clone that did not finish, whatever the error's
    // fields and whether or not the URL has a user name and password.
    expect(r.stderr).not.toContain('git was not found');
    expect(r.stderr).not.toContain('Could not clone repository');
    expect(r.stderr).not.toContain('Verify the URL is accessible');
    expect(r.stderr).not.toContain('timed out');
    expect(output).not.toContain(SECRET);
    expect(output).not.toContain(USER);
  });
});

// A user name or password in the URL does not change which lines a clone
// whose git error says `Timeout was reached` prints: the `timed out` lines,
// which name only the URL as shown, never git's own error lines.
describe('check <git URL> whose git error holds the word `Timeout` says that it timed out', () => {
  it.each(URLS.map((u, i) => ({ ...u, i })))('for $kind', ({ shown, i }) => {
    const r = timeoutWordRuns[i];
    const output = r.stdout + r.stderr;
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).toContain(`Error: Fetching "${shown}" timed out. The target may be too large.`);
    expect(r.stderr).toContain('Try downloading manually and scanning the local path:');
    expect(r.stderr).toMatch(/ check \.\/downloaded-dir\/$/m);
    expect(r.stderr).not.toContain('Could not clone repository');
    expect(r.stderr).not.toContain('Command failed');
    expect(r.stderr).not.toContain('fatal:');
    expect(r.stderr).toContain(`${shown} could not be fetched, so nothing was scanned.`);
    expect(output).not.toContain(SECRET);
    expect(output).not.toContain(USER);
  });

  it('with the same lines for all three, but for the URL they name', () => {
    const [first, ...rest] = URLS.map((u, i) => timeoutWordRuns[i].stderr.split(u.shown).join('<URL>').replace(/Cloning .*\n/, ''));
    expect(first).toContain('timed out');
    for (const other of rest) expect(other).toBe(first);
  });
});
