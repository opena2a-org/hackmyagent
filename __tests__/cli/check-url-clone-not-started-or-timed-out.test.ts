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
 * Hermetic: with no git, PATH is an empty directory. For the time limit,
 * `git` is a stand-in on PATH that never answers, and
 * __tests__/fixtures/git-time-limit-preload.cjs shortens the 120 s the CLI
 * gives it, so Node's own timer ends it. The CLI runs with no proxy variables
 * and with __tests__/helpers/loopback-only.cjs preloaded, so nothing reaches
 * the network. Every credential-bearing URL is assembled at runtime.
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

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

let scratch = '';
let emptyBin = '';
let hangBin = '';
const noGitRuns: Run[] = [];
const timedOutRuns: Run[] = [];

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
}, 400_000);

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
