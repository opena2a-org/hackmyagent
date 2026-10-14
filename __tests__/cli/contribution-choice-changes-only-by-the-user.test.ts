/**
 * The stored contribution choice (`contribute.enabled` in
 * `$OPENA2A_HOME/config.json`) changes only when the user changes it.
 *
 * Before this, two paths changed it on their own:
 *
 *   - Every `secure`, `scan-soul` and `detect` run, `--ci` included, read
 *     `~/.hackmyagent/config.json`. When that legacy file held
 *     `contribute: true` and the stored choice was not `true`, the run wrote
 *     `true`, also over a stored `false`, and later runs contributed. The
 *     legacy file is now left as it is and read by nothing.
 *   - `check` on a GitHub repository or an npm package, from a terminal, asked
 *     `Share scans with the community? [Y/n]` on its third scan and stored
 *     yes for any answer but `n`, Enter included, then shared the scan. It now
 *     asks nothing and shows the tip the other commands show; a scan is shared
 *     when the stored choice is on, as before.
 *
 * Hermetic: each run gets its own HOME and OPENA2A_HOME; `git` is a shim on
 * PATH that copies a local fixture tree; the registry is a capture server on
 * localhost that records every request and answers 503, run in a child process
 * because `spawnSync` blocks this worker's event loop. The CLI runs with
 * __tests__/helpers/loopback-only.cjs preloaded, so a connection to any host
 * but loopback is refused before it is made, with no proxy variables, and
 * with no CI or test-runner marker in its environment, so each run is the
 * terminal run a user makes.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { CI_MARKERS, TEST_RUNNER_MARKERS } from '../../src/telemetry/automation';

// Every case reads a run of the built CLI, so a checkout that has not built
// fails here, naming the command to run, rather than skipping the suite.
beforeAll(assertDistFresh);

const STDIN_TTY_PRELOAD = path.join(__dirname, '..', 'fixtures', 'stdin-tty-preload.cjs');
const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');
const GITHUB_TARGET = 'https://github.com/example-org/example-repo';
const PROMPT = 'Share scans with the community? [Y/n]';
const TIP = 'Tip: Your scans help build community trust data';

const GIT_SHIM = `#!/bin/sh
# Stands in for git: \`git clone ... <dest>\` copies the fixture tree to <dest>.
# Any other git command fails.
if [ "$1" = "clone" ]; then
  for dest in "$@"; do :; done
  mkdir -p "$dest" && cp -R "$HMA_TEST_CLONE_SOURCE/." "$dest/"
  exit $?
fi
exit 1
`;

const SERVER_SRC = `
const http = require('node:http');
const fs = require('node:fs');
const capture = process.argv[2];
const server = http.createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    fs.appendFileSync(capture, JSON.stringify({ method: req.method, url: req.url }) + '\\n');
    res.statusCode = 503;
    res.setHeader('content-type', 'application/json');
    res.end('{"error":"unavailable"}');
  });
});
server.listen(0, 'localhost', () => {
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

// Makes the spawned CLI's standard output a terminal too, so `check` reaches
// the branch that shows the tip.
const STDOUT_TTY_PRELOAD_SRC = `Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });\n`;

interface CapturedRequest { method: string; url: string }

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  /** The requests the registry received during this run, in order. */
  requests: CapturedRequest[];
}

interface Homes { home: string; opena2aHome: string }

let scratch = '';
let source = '';
let binDir = '';
let capturePath = '';
let stdoutTtyPreload = '';
let base = '';
let serverProc: ChildProcess | undefined;

function captured(): CapturedRequest[] {
  const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
  return raw.split('\n').filter(Boolean).map((line) => JSON.parse(line) as CapturedRequest);
}

function homes(label: string, config?: unknown, legacyConfig?: unknown): Homes {
  const dir = path.join(scratch, label);
  const home = path.join(dir, 'home');
  const opena2aHome = path.join(dir, 'opena2a');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });
  if (config !== undefined) {
    fs.writeFileSync(path.join(opena2aHome, 'config.json'), JSON.stringify(config, null, 2) + '\n');
  }
  if (legacyConfig !== undefined) {
    fs.mkdirSync(path.join(home, '.hackmyagent'), { recursive: true });
    fs.writeFileSync(path.join(home, '.hackmyagent', 'config.json'), JSON.stringify(legacyConfig, null, 2) + '\n');
  }
  return { home, opena2aHome };
}

function storedConfig(h: Homes): { contribute?: { enabled?: boolean } } {
  const p = path.join(h.opena2aHome, 'config.json');
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : {};
}

function run(h: Homes, args: string[], opts: { preload?: string[]; input?: string } = {}): Run {
  // Runs are sequential and the CLI has exited, its requests answered, by the
  // time spawnSync returns, so the requests after `before` are this run's.
  const before = captured().length;
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  // A proxy on loopback would carry a request on to the network.
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  for (const name of [...CI_MARKERS, ...TEST_RUNNER_MARKERS, 'NODE_ENV']) delete env[name];
  const preloads = (opts.preload ?? []).flatMap((p) => ['--require', p]);
  const r = spawnSync(process.execPath, [...preloads, CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    input: opts.input ?? '',
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: h.home,
      OPENA2A_HOME: h.opena2aHome,
      REGISTRY_URL: base,
      PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ''}`,
      HMA_TEST_CLONE_SOURCE: source,
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '', requests: captured().slice(before) };
}

function contributePosts(r: Run): CapturedRequest[] {
  return r.requests.filter((q) => q.method === 'POST' && q.url.startsWith('/api/v1/contribute'));
}

function publishPosts(r: Run): CapturedRequest[] {
  return r.requests.filter((q) => q.method === 'POST' && q.url === '/api/v1/trust/publish');
}

/** `secure`'s contribution queue, which @opena2a/contribute keeps under HOME. */
function contributeQueue(h: Homes): string {
  return path.join(h.home, '.opena2a', 'contribute-queue.json');
}

beforeAll(async () => {
  // Removed when this file finishes, after the afterAll below stops the server.
  scratch = tempDir('hma-contribute-choice-');
  source = path.join(scratch, 'source');
  binDir = path.join(scratch, 'bin');
  capturePath = path.join(scratch, 'capture.jsonl');
  stdoutTtyPreload = path.join(scratch, 'stdout-tty-preload.cjs');
  fs.mkdirSync(source, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({ name: 'example-repo', version: '1.0.0' }, null, 2) + '\n');
  fs.writeFileSync(path.join(source, 'index.js'), "module.exports = function greet(name) { return 'hello ' + name; };\n");
  fs.writeFileSync(path.join(source, 'README.md'), '# example-repo\n\nA small library.\n');
  fs.writeFileSync(path.join(binDir, 'git'), GIT_SHIM, { mode: 0o755 });
  fs.writeFileSync(stdoutTtyPreload, STDOUT_TTY_PRELOAD_SRC);

  const serverFile = path.join(scratch, 'server.js');
  fs.writeFileSync(serverFile, SERVER_SRC);
  serverProc = spawn(process.execPath, [serverFile, capturePath], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('capture server did not start')), 10_000);
    serverProc!.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    serverProc!.once('exit', () => { clearTimeout(t); reject(new Error('capture server exited')); });
  });
  // Plain http is accepted for a registry on localhost only.
  base = `http://localhost:${port}`;
}, 30_000);

afterAll(() => {
  serverProc?.kill();
});

describe('a legacy ~/.hackmyagent/config.json does not change the stored choice', () => {
  const LEGACY = { contribute: true, scanCount: 7 };

  it('a stored false stays false through `secure --ci` and `secure`, and nothing is queued or sent', () => {
    const h = homes('legacy-over-false', { contribute: { enabled: false } }, LEGACY);
    const legacyBefore = fs.readFileSync(path.join(h.home, '.hackmyagent', 'config.json'), 'utf8');

    const ciRun = run(h, ['secure', source, '--ci']);
    expect(ciRun.status, ciRun.stderr).not.toBeNull();
    expect(storedConfig(h).contribute?.enabled).toBe(false);

    const textRun = run(h, ['secure', source]);
    expect(textRun.status, textRun.stderr).not.toBeNull();
    expect(storedConfig(h).contribute?.enabled).toBe(false);
    expect(fs.existsSync(contributeQueue(h))).toBe(false);
    expect(contributePosts(ciRun)).toHaveLength(0);
    expect(contributePosts(textRun)).toHaveLength(0);
    // The legacy file is left as it was.
    expect(fs.readFileSync(path.join(h.home, '.hackmyagent', 'config.json'), 'utf8')).toBe(legacyBefore);
  }, 240_000);

  it('a home with no stored choice still has none after `secure`, and nothing is queued', () => {
    const h = homes('legacy-over-unset', undefined, LEGACY);

    const r = run(h, ['secure', source]);
    expect(r.status, r.stderr).not.toBeNull();
    expect(storedConfig(h).contribute?.enabled).toBeUndefined();
    expect(fs.existsSync(contributeQueue(h))).toBe(false);
    expect(contributePosts(r)).toHaveLength(0);
  }, 120_000);
});

describe('`check` asks nothing and shares only on the stored choice', () => {
  it('the third scan from a terminal, answered with Enter, shows the tip, stores nothing and shares nothing', () => {
    // Two scans recorded already, so this run is the third: the one that asked.
    const h = homes('third-scan-enter', { telemetry: { scanCount: 2 } });

    const r = run(h, ['check', GITHUB_TARGET], { preload: [STDIN_TTY_PRELOAD, stdoutTtyPreload], input: '\n' });
    expect(r.status, r.stderr).not.toBeNull();
    expect(r.stdout + r.stderr).not.toContain(PROMPT);
    expect(r.stdout).toContain(TIP);
    expect(storedConfig(h).contribute?.enabled).toBeUndefined();
    expect(publishPosts(r)).toHaveLength(0);
  }, 120_000);

  it('a fresh home from a terminal shares nothing and asks nothing', () => {
    const h = homes('fresh-home');

    const r = run(h, ['check', GITHUB_TARGET], { preload: [STDIN_TTY_PRELOAD], input: '\n' });
    expect(r.status, r.stderr).not.toBeNull();
    expect(r.stdout + r.stderr).not.toContain(PROMPT);
    expect(storedConfig(h).contribute?.enabled).toBeUndefined();
    expect(publishPosts(r)).toHaveLength(0);
  }, 120_000);

  it('with the stored choice on, a scan from a terminal is shared once and nothing is asked', () => {
    const h = homes('stored-on', { contribute: { enabled: true }, telemetry: { scanCount: 2 } });

    const r = run(h, ['check', GITHUB_TARGET], { preload: [STDIN_TTY_PRELOAD], input: '\n' });
    expect(r.status, r.stderr).not.toBeNull();
    expect(r.stdout + r.stderr).not.toContain(PROMPT);
    expect(r.stdout).not.toContain(TIP);
    expect(storedConfig(h).contribute?.enabled).toBe(true);
    expect(publishPosts(r)).toHaveLength(1);
  }, 120_000);
});
