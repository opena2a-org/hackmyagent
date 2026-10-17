/**
 * `secure --ci-publish` sends the `origin` remote URL to the registry as
 * `repoUrl`. A URL that starts with `scheme://`, with or without git's
 * `<transport>::` prefix before it, is sent without the user name and
 * password (or token) in it; a remote with neither is sent as it is; the
 * scp-style `git@github.com:org/repo.git` is sent as it is; and an origin that
 * is a path on this machine is not sent at all.
 *
 * A CI checkout often writes its job token into the remote, as in
 * `https://gitlab-ci-token:<token>@gitlab.com/org/repo.git`. Before this,
 * `--ci-publish` read `git remote get-url origin` and placed the URL in the
 * request body as it came back, token included.
 *
 * Hermetic: each project is a scratch git repository whose `origin` holds the
 * form under test, with a synthetic token where it carries one; the registry
 * is a capture server on localhost that records every request and accepts it.
 * The server runs in a child process because `spawnSync` blocks this worker's
 * event loop. The CLI runs with no proxy variables and with
 * __tests__/helpers/loopback-only.cjs preloaded through NODE_OPTIONS, so a
 * connection to any host but loopback is refused before it is made. Every
 * credential-bearing URL is assembled at runtime.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';
import { setOriginUrlCommand } from '../../src/ui/fail-closed-commands';

// The cases read runs of the built CLI, so a checkout that has not built
// fails here, naming the command to run, rather than skipping the suite.
beforeAll(assertDistFresh);

const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');

const USER = 'gitlab-ci-token';
const TOKEN = ['FAKE', 'NOT', 'A', 'TOKEN', '0000'].join('-');
const CI_PATH = '/api/v1/registry/ci/scan-result';

interface OriginCase {
  name: string;
  remote: string;
  /** The `repoUrl` the registry receives, or null when nothing is sent. */
  sent: string | null;
}

const CASES: OriginCase[] = [
  {
    name: 'https URL with a user name and token',
    remote: `https://${USER}:${TOKEN}@gitlab.com/org/repo.git`,
    sent: 'https://gitlab.com/org/repo.git',
  },
  {
    name: 'https URL with neither',
    remote: 'https://github.com/org/repo.git',
    sent: 'https://github.com/org/repo.git',
  },
  {
    name: 'ssh URL with a user name',
    remote: 'ssh://git@github.com/org/repo.git',
    sent: 'ssh://github.com/org/repo.git',
  },
  {
    name: 'scp-style remote',
    remote: 'git@github.com:org/repo.git',
    sent: 'git@github.com:org/repo.git',
  },
  {
    name: '<transport>:: remote with a user name and token',
    remote: `https::https://${USER}:${TOKEN}@gitlab.com/org/repo.git`,
    sent: 'https::https://gitlab.com/org/repo.git',
  },
  {
    name: 'URL whose scheme starts with a digit, with a user name and token',
    remote: `3ssh://${USER}:${TOKEN}@host.example/org/repo.git`,
    sent: '3ssh://host.example/org/repo.git',
  },
  {
    name: 'local path',
    remote: '/srv/git/org/repo.git',
    sent: null,
  },
];

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
interface CaseRun { status: number | null; stdout: string; stderr: string; ciPosts: CapturedRequest[] }

const git = (dir: string, ...args: string[]) =>
  execFileSync('git', ['-C', dir, ...args], { env: gitFreeEnv(), encoding: 'utf8' }).trim();

let serverProc: ChildProcess | undefined;
const runs = new Map<string, CaseRun>();

function readCiPosts(capturePath: string): CapturedRequest[] {
  const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
  return raw.split('\n').filter(Boolean)
    .map((line) => JSON.parse(line) as CapturedRequest)
    .filter((q) => q.method === 'POST' && q.url === CI_PATH);
}

beforeAll(async () => {
  // Removed when this file finishes, after the afterAll below stops the server.
  const scratch = tempDir('hma-ci-publish-userinfo-');
  const home = path.join(scratch, 'home');
  const opena2aHome = path.join(scratch, 'opena2a');
  const capturePath = path.join(scratch, 'capture.jsonl');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });

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

  for (const [i, c] of CASES.entries()) {
    const project = path.join(scratch, `project-${i}`);
    fs.mkdirSync(project, { recursive: true });
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'example-repo', version: '1.0.0' }, null, 2) + '\n');
    fs.writeFileSync(path.join(project, 'index.js'), "module.exports = function greet(name) { return 'hello ' + name; };\n");
    // No commit is made, so the fixture needs no identity.
    initThrowawayRepo(project, false);
    git(project, 'remote', 'add', 'origin', c.remote);

    const before = readCiPosts(capturePath).length;
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
        // `--ci-publish` accepts a plain-http registry only on this machine.
        REGISTRY_URL: `http://localhost:${port}`,
        CI_SCAN_HMAC_SECRET: 'fake-test-secret',
        NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
      },
    });
    runs.set(c.name, {
      status: r.status,
      stdout: r.stdout ?? '',
      stderr: r.stderr ?? '',
      ciPosts: readCiPosts(capturePath).slice(before),
    });
  }
}, 600_000);

afterAll(() => {
  serverProc?.kill();
});

const context = (run: CaseRun) => `stdout:\n${run.stdout}\nstderr:\n${run.stderr}`;

describe('secure --ci-publish: the origin URL reaches the registry without its userinfo', () => {
  for (const c of CASES.filter((x) => x.sent !== null)) {
    describe(c.name, () => {
      it('sends exactly one CI scan result', () => {
        const run = runs.get(c.name)!;
        expect(run.ciPosts, context(run)).toHaveLength(1);
        expect(run.stdout).toContain('CI scan result submitted to registry.');
      });

      it(`publishes repoUrl as ${c.sent}`, () => {
        const body = JSON.parse(runs.get(c.name)!.ciPosts[0].body) as Record<string, unknown>;
        expect(body.repoUrl).toBe(c.sent);
      });

      it('carries no token anywhere in the body', () => {
        expect(runs.get(c.name)!.ciPosts[0].body).not.toContain(TOKEN);
      });
    });
  }

  it('carries neither the token nor the user name of a URL that held both', () => {
    for (const c of CASES.filter((x) => x.remote.includes(`${USER}:${TOKEN}@`))) {
      const raw = runs.get(c.name)!.ciPosts[0].body;
      expect(raw, c.name).not.toContain(TOKEN);
      expect(raw, c.name).not.toContain(USER);
    }
  });
});

describe('secure --ci-publish: an origin that is a local path', () => {
  it('sends nothing and says why, with the commands to check and set origin', () => {
    const run = runs.get('local path')!;
    expect(run.ciPosts, context(run)).toHaveLength(0);
    expect(run.stdout).not.toContain('CI scan result submitted to registry.');
    expect(run.stderr).toContain('The git remote origin is a local path, not a repository URL, so the CI scan result was not sent.');
    expect(run.stderr).toContain('git remote get-url origin');
    // The operand fails closed when pasted unset (#1132); the paste itself is
    // measured in __tests__/ui/fix-verify-spans-fail-closed.test.ts.
    expect(run.stderr).toContain(`Set it to the repository URL: ${setOriginUrlCommand()}`);
    expect(run.stderr).toContain('git remote set-url origin "${REPO_URL:?set REPO_URL to the repository URL');
    expect(run.stderr).not.toContain('<host>');
  });
});
