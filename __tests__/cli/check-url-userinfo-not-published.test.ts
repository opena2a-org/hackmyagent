/**
 * `check <git URL>` with a user name and password (or token) in the URL hands
 * them to `git clone` and to nothing else.
 *
 * Before this, the name of the scan `check` shares with the registry (with
 * contribution on and a terminal on standard input) was the URL without its
 * scheme, userinfo included, and a share that failed queued the same name in
 * `$OPENA2A_HOME/hma-pending-scans.json`, which the next share sends. The run
 * printed it in its `Cloning ...` line, its header and its Next Steps, and
 * `--json` carried it in `name` and `url`. A clone that failed quoted it in
 * the error line and in the `--json` `target`.
 *
 * Hermetic: `git` is a shim on PATH that records its arguments and copies a
 * local fixture tree; the registry is a capture server on localhost that
 * records every request and answers 503, so the scan is also queued; and
 * contribution is switched on in a scratch OPENA2A_HOME. The server runs in a
 * child process because `spawnSync` blocks this worker's event loop. The CLI
 * runs with no proxy variables and with __tests__/helpers/loopback-only.cjs
 * preloaded through NODE_OPTIONS, so a Node process it starts has it too: a
 * connection to any host but loopback is refused before it is made. That
 * includes what a scan with contribution on sends beyond the registry it is
 * given, the classification telemetry and, under a fresh HOME, the classifier
 * download. Nothing reaches the network. Every credential-bearing URL is
 * assembled at runtime.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

// Every case reads a run of the built CLI, so a checkout that has not built
// fails here, naming the command to run, rather than skipping the suite.
beforeAll(assertDistFresh);

const TTY_PRELOAD = path.join(__dirname, '..', 'fixtures', 'stdin-tty-preload.cjs');
const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');

const USER = 'fakeuser';
const SECRET = ['FAKE', 'secret', '123'].join('');
const REPO = 'gitlab.com/example-org/example-repo';
const LEGACY_REPO = 'gitlab.com/example-org/legacy-repo';
const TYPED_URL = `https://${USER}:${SECRET}@${REPO}.git`;
const SHOWN_URL = `https://${REPO}.git`;

const GIT_SHIM = `#!/bin/sh
# Stands in for git: \`git clone ... <url> <dest>\` records its arguments and
# copies the fixture tree to <dest>, or fails when HMA_TEST_GIT_FAIL is set.
# Any other git command fails.
if [ "$1" = "clone" ]; then
  printf '%s\\n' "$@" > "$HMA_TEST_GIT_ARGS"
  if [ -n "$HMA_TEST_GIT_FAIL" ]; then
    echo "fatal: unable to access the repository" >&2
    exit 1
  fi
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
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    fs.appendFileSync(capture, JSON.stringify({ method: req.method, url: req.url, headers: req.headers, body }) + '\\n');
    res.statusCode = 503;
    res.setHeader('content-type', 'application/json');
    res.end('{"error":"unavailable"}');
  });
});
server.listen(0, 'localhost', () => {
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

interface CapturedRequest { method: string; url: string; body: string }

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  gitArgs: string[];
  pendingText: string | null;
  /** The requests the registry received during this run, in order. */
  requests: CapturedRequest[];
  /** The connections the CLI opened, `allowed <host>:<port>` or `refused <host>:<port>`. */
  connections: string[];
}

let scratch = '';
let source = '';
let binDir = '';
let capturePath = '';
let base = '';
let serverProc: ChildProcess | undefined;
let textRun: Run;
let jsonRun: Run;
let failedCloneRun: Run;
let legacyQueueRun: Run;

function captured(): { raw: string; requests: CapturedRequest[] } {
  const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
  return { raw, requests: raw.split('\n').filter(Boolean).map((line) => JSON.parse(line) as CapturedRequest) };
}

function publishPosts(r: Run): CapturedRequest[] {
  return r.requests.filter((q) => q.method === 'POST' && q.url === '/api/v1/trust/publish');
}

function run(label: string, extraArgs: string[], extraEnv: NodeJS.ProcessEnv = {}, pendingSeed?: unknown[]): Run {
  const dir = path.join(scratch, label);
  const home = path.join(dir, 'home');
  const opena2aHome = path.join(dir, 'opena2a');
  const gitArgsPath = path.join(dir, 'git-args.txt');
  const connectLogPath = path.join(dir, 'connections.txt');
  const pendingPath = path.join(opena2aHome, 'hma-pending-scans.json');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });
  fs.writeFileSync(path.join(opena2aHome, 'config.json'), JSON.stringify({ contribute: { enabled: true } }) + '\n');
  if (pendingSeed) fs.writeFileSync(pendingPath, JSON.stringify(pendingSeed, null, 2));

  // Runs are sequential and the CLI has exited, its requests answered, by the
  // time spawnSync returns, so the requests after `before` are this run's.
  const before = captured().requests.length;
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  // A proxy on loopback would carry a request on to the network.
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, ['--require', TTY_PRELOAD, CLI, 'check', TYPED_URL, ...extraArgs], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: opena2aHome,
      REGISTRY_URL: base,
      PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ''}`,
      HMA_TEST_CLONE_SOURCE: source,
      HMA_TEST_GIT_ARGS: gitArgsPath,
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
      HMA_TEST_CONNECT_LOG: connectLogPath,
      ...extraEnv,
    },
  });
  return {
    status: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    gitArgs: fs.existsSync(gitArgsPath) ? fs.readFileSync(gitArgsPath, 'utf8').split('\n').filter(Boolean) : [],
    pendingText: fs.existsSync(pendingPath) ? fs.readFileSync(pendingPath, 'utf8') : null,
    requests: captured().requests.slice(before),
    connections: fs.existsSync(connectLogPath) ? fs.readFileSync(connectLogPath, 'utf8').split('\n').filter(Boolean) : [],
  };
}

function jsonDocument(stdout: string): Record<string, unknown> {
  return JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1));
}

beforeAll(async () => {
  // Removed when this file finishes, after the afterAll below stops the server.
  scratch = tempDir('hma-url-userinfo-');
  source = path.join(scratch, 'source');
  binDir = path.join(scratch, 'bin');
  capturePath = path.join(scratch, 'capture.jsonl');
  fs.mkdirSync(source, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({ name: 'example-repo', version: '1.0.0' }, null, 2) + '\n');
  fs.writeFileSync(path.join(source, 'index.js'), "module.exports = function greet(name) { return 'hello ' + name; };\n");
  fs.writeFileSync(path.join(source, 'README.md'), '# example-repo\n\nA small library.\n');
  fs.writeFileSync(path.join(binDir, 'git'), GIT_SHIM, { mode: 0o755 });

  const serverFile = path.join(scratch, 'server.js');
  fs.writeFileSync(serverFile, SERVER_SRC);
  serverProc = spawn(process.execPath, [serverFile, capturePath], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('capture server did not start')), 10_000);
    serverProc!.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    serverProc!.once('exit', () => { clearTimeout(t); reject(new Error('capture server exited')); });
  });
  // `check` accepts a plain-http registry only on localhost.
  base = `http://localhost:${port}`;

  textRun = run('text', []);
  jsonRun = run('json', ['--json']);
  failedCloneRun = run('failed-clone', ['--json'], { HMA_TEST_GIT_FAIL: '1' });
  // The queue as an earlier version left it after a failed share.
  legacyQueueRun = run('legacy-queue', [], {}, [{
    name: `${USER}:${SECRET}@${LEGACY_REPO}`,
    score: 90,
    maxScore: 100,
    projectType: 'library',
    findingCount: 1,
    timestamp: '2026-10-01T00:00:00.000Z',
  }]);
}, 300_000);

afterAll(() => {
  serverProc?.kill();
});

describe('check <git URL> keeps the URL\'s userinfo out of what it prints and publishes', () => {
  it('harness: the run clones through the shim with the URL as typed, and shares one scan', () => {
    expect(textRun.status, textRun.stderr).toBe(0);
    expect(textRun.gitArgs[0]).toBe('clone');
    expect(textRun.gitArgs).toContain(TYPED_URL);
    expect(publishPosts(textRun)).toHaveLength(1);
  });

  it('harness: the CLI\'s connections pass through the loopback-only preload, which let none leave loopback', () => {
    // The share reached the capture server through the preload, so the
    // preload is loaded and on the path the CLI's requests take.
    expect(textRun.connections).toContain(`allowed ${new URL(base).host}`);
    const allowed = [textRun, jsonRun, failedCloneRun, legacyQueueRun]
      .flatMap((r) => r.connections)
      .filter((c) => c.startsWith('allowed '));
    for (const c of allowed) expect(c).toMatch(/^allowed (localhost|127(\.\d{1,3}){3}|::1|\[::1\]):\d+$/);
  });

  it('the scan it publishes is named by host and path, without the userinfo', () => {
    const [post] = publishPosts(textRun);
    expect(JSON.parse(post.body).name).toBe(REPO);
    expect(post.body).not.toContain(SECRET);
    expect(post.body).not.toContain(USER);
  });

  it('no request the registry received, in any run here, carries any part of the userinfo', () => {
    const { raw, requests } = captured();
    expect(requests.length).toBeGreaterThan(0);
    expect(raw).not.toContain(SECRET);
    expect(raw).not.toContain(USER);
  });

  it('the scan queued after the failed share has the same name', () => {
    expect(textRun.pendingText, 'the 503 should leave the scan queued').not.toBeNull();
    const queued = JSON.parse(textRun.pendingText!) as Array<{ name: string }>;
    expect(queued.map((q) => q.name)).toEqual([REPO]);
    expect(textRun.pendingText).not.toContain(SECRET);
    expect(textRun.pendingText).not.toContain(USER);
  });

  it('the terminal output names the repository without the userinfo', () => {
    expect(textRun.stderr).toContain(`Cloning ${REPO}...`);
    const output = textRun.stdout + textRun.stderr;
    expect(output).toContain(REPO);
    expect(output).not.toContain(SECRET);
    expect(output).not.toContain(USER);
  });

  it('--json reports the URL and the name without the userinfo, and shares nothing', () => {
    expect(jsonRun.gitArgs).toContain(TYPED_URL);
    const doc = jsonDocument(jsonRun.stdout);
    expect(doc.url).toBe(SHOWN_URL);
    expect(doc.name).toBe(REPO);
    expect(jsonRun.stdout + jsonRun.stderr).not.toContain(SECRET);
    expect(jsonRun.stdout + jsonRun.stderr).not.toContain(USER);
    expect(jsonRun.pendingText).toBeNull();
    expect(publishPosts(jsonRun)).toHaveLength(0);
  });

  it('a clone that fails is reported without the userinfo, in its error line and its --json target', () => {
    expect(failedCloneRun.status, failedCloneRun.stderr).toBe(2);
    expect(failedCloneRun.gitArgs).toContain(TYPED_URL);
    // The error quotes the failed command line, with the URL as it is shown.
    expect(failedCloneRun.stderr).toContain(`--single-branch ${SHOWN_URL} `);
    expect(jsonDocument(failedCloneRun.stdout).target).toBe(SHOWN_URL);
    expect(failedCloneRun.stdout + failedCloneRun.stderr).not.toContain(SECRET);
    expect(failedCloneRun.stdout + failedCloneRun.stderr).not.toContain(USER);
    expect(failedCloneRun.pendingText).toBeNull();
    expect(publishPosts(failedCloneRun)).toHaveLength(0);
  });

  it('a scan an earlier version queued under the userinfo name is sent and kept under the name without it', () => {
    const names = publishPosts(legacyQueueRun).map((p) => JSON.parse(p.body).name as string);
    expect(names.sort()).toEqual([REPO, LEGACY_REPO].sort());
    for (const post of publishPosts(legacyQueueRun)) {
      expect(post.body).not.toContain(SECRET);
      expect(post.body).not.toContain(USER);
    }
    // Both shares failed (503). The queue keeps the earlier scan under the
    // name without the userinfo. Whether it also holds the new scan depends
    // on which of the two shares is answered first, so both are accepted.
    const queued = JSON.parse(legacyQueueRun.pendingText!) as Array<{ name: string }>;
    expect(queued.map((q) => q.name)).toContain(LEGACY_REPO);
    for (const q of queued) expect([REPO, LEGACY_REPO]).toContain(q.name);
    expect(legacyQueueRun.pendingText).not.toContain(SECRET);
    expect(legacyQueueRun.pendingText).not.toContain(USER);
  });
});
