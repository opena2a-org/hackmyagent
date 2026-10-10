/**
 * `attack --registry-report` and `attack --publish` send the registry one
 * name for one target: the URL without its userinfo, where the URL parser
 * behind `fetch` (which sends the payloads) ends the authority.
 *
 * Before: `--publish` removed the userinfo from the name it sends and
 * `--registry-report` did not. With target `http://@localhost:<port>/...`
 * one run sent `http://@localhost:<port>/...` to `request-scan-token` and
 * `scan-result` (in `packageName` and in the report's `target`) and
 * `http://localhost:<port>/...` to `trust/publish`.
 *
 * A URL with no userinfo is sent as typed, also when a `\` puts an `@` after
 * the host: `fetch` reads `http://localhost:<port>\@evil.example/...` as a
 * path on localhost, so that is the host the run measured.
 *
 * Hermetic: one stub in its own process (an in-process server never accepts
 * while `spawnSync` blocks the event loop) answers every request with an
 * OpenAI-style reply and records it, so it is both the target and the
 * registry. The CLI runs with __tests__/helpers/loopback-only.cjs preloaded,
 * no proxy variables and a scratch HOME, from a scratch working directory
 * (`--publish` hashes the working directory).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');

const STUB_SRC = `
const http = require('node:http');
const fs = require('node:fs');
const capture = process.argv[2];
const server = http.createServer((req, res) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    fs.appendFileSync(capture, JSON.stringify({ method: req.method, url: req.url, body }) + '\\n');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message: { content: 'The weather today is mild with light wind.' } }] }));
  });
});
server.listen(0, 'localhost', () => process.stdout.write(String(server.address().port) + '\\n'));
`;

interface CapturedRequest { method: string; url: string; body: string }
interface Run { status: number | null; out: string; requests: CapturedRequest[]; connections: string[] }

let scratch = '';
let capturePath = '';
let base = '';
let stub: ChildProcess | undefined;
let backslashRun: Run;
let emptyUserinfoRun: Run;
let backslashTarget = '';
let emptyUserinfoTarget = '';

function captured(): CapturedRequest[] {
  const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
  return raw.split('\n').filter(Boolean).map((line) => JSON.parse(line) as CapturedRequest);
}

function attack(label: string, target: string, flags: string[]): Run {
  const dir = path.join(scratch, label);
  const home = path.join(dir, 'home');
  const cwd = path.join(dir, 'cwd');
  const connectLog = path.join(dir, 'connections.txt');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(cwd, { recursive: true });
  const before = captured().length;
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.HMA_SCANNER_SIGNING_KEY;
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, [
    CLI, 'attack', target, ...flags, '--category', 'prompt-injection', '--intensity', 'passive',
    '--delay', '0', '--timeout', '5000',
  ], {
    cwd,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: path.join(home, '.opena2a'),
      REGISTRY_URL: base,
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
      HMA_TEST_CONNECT_LOG: connectLog,
    },
  });
  return {
    status: r.status,
    out: (r.stdout ?? '') + (r.stderr ?? ''),
    requests: captured().slice(before),
    connections: fs.existsSync(connectLog) ? fs.readFileSync(connectLog, 'utf8').split('\n').filter(Boolean) : [],
  };
}

function posts(r: Run, url: string): Array<Record<string, any>> {
  return r.requests.filter((q) => q.method === 'POST' && q.url === url).map((q) => JSON.parse(q.body));
}

beforeAll(async () => {
  scratch = tempDir('hma-attack-name-');
  capturePath = path.join(scratch, 'capture.jsonl');
  const stubFile = path.join(scratch, 'stub.js');
  fs.writeFileSync(stubFile, STUB_SRC);
  stub = spawn(process.execPath, [stubFile, capturePath], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('stub did not start')), 15_000);
    stub!.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    stub!.once('exit', () => { clearTimeout(t); reject(new Error('stub exited')); });
  });
  // A plain-http registry is accepted only on localhost.
  base = `http://localhost:${port}`;
  backslashTarget = `${base}\\@evil.example/v1/chat/completions`;
  emptyUserinfoTarget = `http://@localhost:${port}/v1/chat/completions`;
  backslashRun = attack('backslash', backslashTarget, ['--publish']);
  emptyUserinfoRun = attack('empty-userinfo', emptyUserinfoTarget, ['--registry-report', '--publish']);
}, 400_000);

afterAll(() => {
  stub?.kill();
});

describe('attack sends the registry one name for a target URL', () => {
  it('harness: the payloads reached the stub, and no connection left loopback', () => {
    for (const r of [backslashRun, emptyUserinfoRun]) {
      expect(r.requests.some((q) => q.url.endsWith('/v1/chat/completions')), r.out).toBe(true);
      expect(r.connections.length, r.out).toBeGreaterThan(0);
      for (const c of r.connections.filter((x) => x.startsWith('allowed '))) {
        expect(c).toMatch(/^allowed (localhost|127(\.\d{1,3}){3}|::1|\[::1\]):\d+$/);
      }
      expect(r.connections.filter((x) => x.startsWith('refused '))).toEqual([]);
    }
  });

  it('--publish names a target whose `\\` puts an `@` after the host by the URL as typed', () => {
    // fetch read the host as localhost and the rest as the path.
    expect(backslashRun.requests.map((q) => q.url)).toContain('/@evil.example/v1/chat/completions');
    const published = posts(backslashRun, '/api/v1/trust/publish');
    expect(published, backslashRun.out).toHaveLength(1);
    expect(published[0].name).toBe(backslashTarget);
    expect(posts(backslashRun, '/api/v1/registry/community/request-scan-token').map((b) => b.packageName))
      .toEqual([backslashTarget]);
  });

  it('--registry-report and --publish send the same name, without the empty userinfo', () => {
    const expected = `http://localhost:${new URL(base).port}/v1/chat/completions`;
    const tokenNames = posts(emptyUserinfoRun, '/api/v1/registry/community/request-scan-token').map((b) => b.packageName);
    const reports = posts(emptyUserinfoRun, '/api/v1/registry/community/scan-result');
    const published = posts(emptyUserinfoRun, '/api/v1/trust/publish');
    expect(tokenNames, emptyUserinfoRun.out).toHaveLength(2);
    expect(reports, emptyUserinfoRun.out).toHaveLength(1);
    expect(published, emptyUserinfoRun.out).toHaveLength(1);
    expect(tokenNames).toEqual([expected, expected]);
    expect(reports[0].packageName).toBe(expected);
    expect(reports[0].rawReport.target).toBe(expected);
    expect(published[0].name).toBe(expected);
  });
});
