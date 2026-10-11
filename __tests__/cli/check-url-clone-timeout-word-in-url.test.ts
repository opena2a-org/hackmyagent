/**
 * #1003 — `check <git URL>` decides that a clone timed out from what git
 * wrote, not from the URL.
 *
 * Before: the word `timeout` was looked for in the whole error message, which
 * starts with the failed command line and so holds the URL as typed and the
 * directory named after it. A URL whose password or path held `timeout` or
 * `Timeout` printed `Error: Fetching "<URL>" timed out.` for any clone failure
 * whose message held neither `128` nor `not found`, such as an authentication
 * failure. Now the word is read from git's stderr, with the URLs and the
 * quoted paths in git's lines taken out.
 *
 * Hermetic: `git` is a stand-in on PATH that writes git's own lines and exits
 * 128, the CLI runs with no proxy variables and with
 * __tests__/helpers/loopback-only.cjs preloaded, so nothing reaches the
 * network. Every credential-bearing URL is assembled at runtime.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');

const USER = 'fakeuser';
const SECRET = ['FAKE', 'Timeout', '123'].join('');
const REPO = 'gitlab.com/example-org/example-repo';

// Stands in for a git whose clone is refused: it writes the `Cloning into`
// line and the authentication failure, quoting the URL as typed, and exits
// 128 as git does.
const GIT_AUTH_FAILS = `#!/bin/sh
for arg in "$@"; do
  case "$arg" in https://*) url="$arg" ;; esac
  dest="$arg"
done
printf "Cloning into '%s'...\\n" "$dest" >&2
printf "fatal: Authentication failed for '%s'\\n" "$url" >&2
exit 128
`;

// Stands in for a git that gives up on the connection itself, quoting the URL
// as typed.
const GIT_SAYS_TIMEOUT = `#!/bin/sh
for arg in "$@"; do
  case "$arg" in https://*) url="$arg" ;; esac
done
printf "fatal: unable to access '%s/': Failed to connect to gitlab.com port 443 after 75002 ms: Timeout was reached\\n" "$url" >&2
exit 128
`;

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

let scratch = '';

function run(label: string, gitScript: string, typedUrl: string): Run {
  const dir = path.join(scratch, label);
  const bin = path.join(dir, 'bin');
  const home = path.join(dir, 'home');
  const opena2aHome = path.join(dir, 'opena2a');
  for (const d of [bin, home, opena2aHome]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(bin, 'git'), gitScript, { mode: 0o755 });

  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  // A proxy on loopback would carry a request on to the network.
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, [CLI, 'check', typedUrl, '--offline'], {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: opena2aHome,
      PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** URLs whose password or path holds the word, as typed and as shown. */
const URLS = [
  { kind: 'a `.git` URL whose password holds `Timeout`', typed: `https://${USER}:${SECRET}@${REPO}.git`, shown: `https://${REPO}.git` },
  { kind: 'a forge URL with no `.git` whose password holds `Timeout`', typed: `https://${USER}:${SECRET}@${REPO}`, shown: `https://${REPO}` },
  { kind: 'a `.git` URL whose path holds `timeout`', typed: 'https://gitlab.com/example-org/timeout-repo.git', shown: 'https://gitlab.com/example-org/timeout-repo.git' },
] as const;

const authRuns: Run[] = [];
const timeoutRuns: Run[] = [];

beforeAll(() => {
  // Removed when this file finishes.
  scratch = tempDir('hma-1003-clone-');
  URLS.forEach(({ typed }, i) => {
    authRuns.push(run(`auth-${i}`, GIT_AUTH_FAILS, typed));
    timeoutRuns.push(run(`timeout-${i}`, GIT_SAYS_TIMEOUT, typed));
  });
}, 600_000);

describe('#1003 check <git URL> whose clone git refused does not say that it timed out', () => {
  it.each(URLS.map((u, i) => ({ ...u, i })))('for $kind', ({ typed, shown, i }) => {
    const r = authRuns[i];
    const output = r.stdout + r.stderr;
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).not.toContain('timed out');
    expect(r.stderr).not.toContain('Try downloading manually');
    expect(r.stderr).toContain(`${shown} could not be fetched, so nothing was scanned.`);
    if (typed !== shown) {
      // A URL with a user name and password gets the lines that name only
      // the URL as shown.
      expect(r.stderr).toContain(`Error: Could not clone repository from "${shown}".`);
      expect(output).not.toContain(SECRET);
      expect(output).not.toContain(USER);
    }
  });
});

describe('#1003 check <git URL> whose git error says `Timeout was reached` still says that it timed out', () => {
  it.each(URLS.map((u, i) => ({ ...u, i })))('for $kind', ({ shown, i }) => {
    const r = timeoutRuns[i];
    const output = r.stdout + r.stderr;
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).toContain(`Error: Fetching "${shown}" timed out. The target may be too large.`);
    expect(r.stderr).not.toContain('Could not clone repository');
    expect(r.stderr).not.toContain('fatal:');
    expect(output).not.toContain(SECRET);
  });
});
