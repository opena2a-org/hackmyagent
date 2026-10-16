/**
 * #1123: `check <URL>` does not share the scan of a downloaded file with the
 * community registry.
 *
 * For an http(s) URL that is not a git URL, `check` downloads the file and
 * names the scan after it: the last segment of the URL path, or `download`
 * when the path ends in `/`. With contribution on and a terminal on standard
 * input, that name was sent as the package `name` of `POST
 * /api/v1/trust/publish`, with no ecosystem, type or version, so a URL ending
 * in `/lodash` published a scan named `lodash`. A failed share queued it in
 * `$OPENA2A_HOME/hma-pending-scans.json`, which the next share sends.
 *
 * The control is a git URL in the same harness: its scan is shared, named by
 * host and path, so the capture server and the terminal preload can see a
 * share when there is one.
 *
 * Hermetic: the file server and the registry are one capture server on
 * loopback that records every request and answers 503 to anything but the
 * files it serves; `git` is a shim on PATH that copies a local fixture tree;
 * and __tests__/helpers/loopback-only.cjs is preloaded, so a connection to
 * any host but loopback is refused before it is made.
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

const GIT_SHIM = `#!/bin/sh
# Stands in for git: \`git clone ... <url> <dest>\` copies the fixture tree to
# <dest>. Any other git command fails.
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
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    fs.appendFileSync(capture, JSON.stringify({ method: req.method, url: req.url, body }) + '\\n');
    if (req.url.startsWith('/files/')) {
      res.setHeader('content-type', 'application/javascript');
      res.end(req.method === 'HEAD' ? undefined : 'module.exports = function add(a, b) { return a + b; };\\n');
      return;
    }
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
  pendingText: string | null;
  requests: CapturedRequest[];
}

let scratch = '';
let source = '';
let binDir = '';
let capturePath = '';
let base = '';
let serverProc: ChildProcess | undefined;
let namedFileRun: Run;
let trailingSlashRun: Run;
let gitControlRun: Run;

function captured(): CapturedRequest[] {
  const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
  return raw.split('\n').filter(Boolean).map((line) => JSON.parse(line) as CapturedRequest);
}

function publishPosts(r: Run): CapturedRequest[] {
  return r.requests.filter((q) => q.method === 'POST' && q.url === '/api/v1/trust/publish');
}

function run(label: string, url: string): Run {
  const dir = path.join(scratch, label);
  const home = path.join(dir, 'home');
  const opena2aHome = path.join(dir, 'opena2a');
  const pendingPath = path.join(opena2aHome, 'hma-pending-scans.json');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });
  fs.writeFileSync(path.join(opena2aHome, 'config.json'), JSON.stringify({ contribute: { enabled: true } }) + '\n');

  // Runs are sequential, so the requests after `before` are this run's.
  const before = captured().length;
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY;
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, ['--require', TTY_PRELOAD, CLI, 'check', url], {
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
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
    },
  });
  return {
    status: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    pendingText: fs.existsSync(pendingPath) ? fs.readFileSync(pendingPath, 'utf8') : null,
    requests: captured().slice(before),
  };
}

beforeAll(async () => {
  // Removed when this file finishes, after the afterAll below stops the server.
  scratch = tempDir('hma-raw-url-share-');
  source = path.join(scratch, 'source');
  binDir = path.join(scratch, 'bin');
  capturePath = path.join(scratch, 'capture.jsonl');
  fs.mkdirSync(source, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({ name: 'example-repo', version: '1.0.0' }, null, 2) + '\n');
  fs.writeFileSync(path.join(source, 'index.js'), "module.exports = function greet(name) { return 'hello ' + name; };\n");
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

  namedFileRun = run('named-file', `${base}/files/lodash`);
  trailingSlashRun = run('trailing-slash', `${base}/files/`);
  gitControlRun = run('git-control', `${base}/example-org/example-repo.git`);
}, 400_000);

afterAll(() => {
  serverProc?.kill();
});

describe('#1123 check <URL> shares no scan of a downloaded file', () => {
  it('harness: the git URL scan is shared, named by host and path, so a share is visible here', () => {
    expect(gitControlRun.status, gitControlRun.stderr).toBe(0);
    const posts = publishPosts(gitControlRun);
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0].body).name).toBe(`${new URL(base).host}/example-org/example-repo`);
  });

  for (const [label, get, file] of [
    ['a URL whose path ends in a package name', () => namedFileRun, '/files/lodash'],
    ['a URL whose path ends in /', () => trailingSlashRun, '/files/'],
  ] as const) {
    it(`${label}: the file is downloaded and scanned`, () => {
      const r = get();
      expect(r.status, r.stderr).toBe(0);
      expect(r.requests.filter((q) => q.url === file).map((q) => q.method)).toEqual(['HEAD', 'GET']);
    });

    it(`${label}: nothing is published and nothing is queued`, () => {
      const r = get();
      expect(publishPosts(r)).toEqual([]);
      expect(r.requests.filter((q) => q.method === 'POST')).toEqual([]);
      expect(r.pendingText).toBeNull();
    });
  }
});
