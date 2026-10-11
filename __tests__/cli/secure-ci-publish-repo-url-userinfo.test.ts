/**
 * `secure --ci-publish` sends the `origin` remote URL to the registry as
 * `repoUrl`. A URL that starts with `scheme://` is sent without the user name
 * and password (or token) in it; a remote in another form, such as the
 * scp-style `git@github.com:org/repo.git`, is sent as it is.
 *
 * A CI checkout often writes its job token into the remote, as in
 * `https://gitlab-ci-token:<token>@gitlab.com/org/repo.git`. Before this,
 * `--ci-publish` read `git remote get-url origin` and placed the URL in the
 * request body as it came back, token included.
 *
 * Hermetic: the project is a scratch git repository whose `origin` holds a
 * synthetic token; the registry is a capture server on localhost that records
 * every request and accepts it. The server runs in a child process because
 * `spawnSync` blocks this worker's event loop. The CLI runs with no proxy
 * variables and with __tests__/helpers/loopback-only.cjs preloaded through
 * NODE_OPTIONS, so a connection to any host but loopback is refused before it
 * is made. The credential-bearing URL is assembled at runtime.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

// The case reads a run of the built CLI, so a checkout that has not built
// fails here, naming the command to run, rather than skipping the suite.
beforeAll(assertDistFresh);

const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');

const USER = 'gitlab-ci-token';
const TOKEN = ['FAKE', 'NOT', 'A', 'TOKEN', '0000'].join('-');
const REMOTE_URL = `https://${USER}:${TOKEN}@gitlab.com/org/repo.git`;
const PUBLISHED_URL = 'https://gitlab.com/org/repo.git';
const CI_PATH = '/api/v1/registry/ci/scan-result';

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
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end('{"valid":true,"trustImpact":"none"}');
  });
});
server.listen(0, 'localhost', () => {
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

interface CapturedRequest { method: string; url: string; body: string }

const git = (dir: string, ...args: string[]) =>
  execFileSync('git', ['-C', dir, ...args], { env: gitFreeEnv(), encoding: 'utf8' }).trim();

let serverProc: ChildProcess | undefined;
let run: { status: number | null; stdout: string; stderr: string };
let ciPosts: CapturedRequest[] = [];

beforeAll(async () => {
  // Removed when this file finishes, after the afterAll below stops the server.
  const scratch = tempDir('hma-ci-publish-userinfo-');
  const project = path.join(scratch, 'project');
  const home = path.join(scratch, 'home');
  const opena2aHome = path.join(scratch, 'opena2a');
  const capturePath = path.join(scratch, 'capture.jsonl');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'example-repo', version: '1.0.0' }, null, 2) + '\n');
  fs.writeFileSync(path.join(project, 'index.js'), "module.exports = function greet(name) { return 'hello ' + name; };\n");

  // No commit is made, so the fixture needs no identity.
  initThrowawayRepo(project, false);
  git(project, 'remote', 'add', 'origin', REMOTE_URL);

  const serverFile = path.join(scratch, 'server.js');
  fs.writeFileSync(serverFile, SERVER_SRC);
  serverProc = spawn(process.execPath, [serverFile, capturePath], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('capture server did not start')), 10_000);
    serverProc!.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    serverProc!.once('exit', () => { clearTimeout(t); reject(new Error('capture server exited')); });
  });

  // The CLI runs `git remote get-url origin`; under a git hook an inherited
  // GIT_DIR would point that at this repository instead of the fixture (#348).
  const env: NodeJS.ProcessEnv = gitFreeEnv();
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  // A proxy on loopback would carry a request on to the network.
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, [CLI, 'secure', project, '--no-machine-posture', '--ci-publish'], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: opena2aHome,
      // `--ci-publish` accepts a plain-http registry only on localhost.
      REGISTRY_URL: `http://localhost:${port}`,
      CI_SCAN_HMAC_SECRET: 'fake-test-secret',
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
    },
  });
  run = { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };

  const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
  ciPosts = raw.split('\n').filter(Boolean)
    .map((line) => JSON.parse(line) as CapturedRequest)
    .filter((q) => q.method === 'POST' && q.url === CI_PATH);
}, 180_000);

afterAll(() => {
  serverProc?.kill();
});

describe('secure --ci-publish: the origin URL reaches the registry without its userinfo', () => {
  it('sends exactly one CI scan result', () => {
    expect(ciPosts, `stdout:\n${run.stdout}\nstderr:\n${run.stderr}`).toHaveLength(1);
    expect(run.stdout).toContain('CI scan result submitted to registry.');
  });

  it('publishes repoUrl as the remote URL with the user name and token removed', () => {
    const body = JSON.parse(ciPosts[0].body) as Record<string, unknown>;
    expect(body.repoUrl).toBe(PUBLISHED_URL);
  });

  it('carries neither the token nor the user name anywhere in the body', () => {
    const body = JSON.parse(ciPosts[0].body) as Record<string, unknown>;
    const whole = JSON.stringify(body);
    expect(whole).not.toContain(TOKEN);
    expect(whole).not.toContain(USER);
    expect(ciPosts[0].body).not.toContain(TOKEN);
    expect(ciPosts[0].body).not.toContain(USER);
  });
});
