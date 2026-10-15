/**
 * A capture registry on localhost and the checks every outbound payload is
 * held to, shared by the outbound contract tests in __tests__/registry/.
 *
 * The registry runs in a child process, because `spawnSync` blocks the test
 * worker's event loop and an in-process server would never answer. It records
 * every request (method, path, scan token header, body) to a JSON-lines file
 * and answers each registry route the CLI calls with the shape that route
 * returns, so the CLI goes on to its next request. `POST /v1/chat/completions`
 * answers as an OpenAI-style agent, so one server is also the `attack` target.
 * A publish is answered with the status written to `<scratch>/publish-status`
 * (200 when the file is absent), which lets a test make a share fail.
 *
 * The CLI runs with __tests__/helpers/loopback-only.cjs preloaded (no
 * connection leaves the host), no proxy variables, no hosted-analysis key and
 * no first-party signing key, from a working directory that is not the target.
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { BUILT_CLI as CLI } from './dist-freshness';
import { gitFreeEnv } from './throwaway-repo';
import { computeTreeHash } from '../../src/registry/publish';

const LOOPBACK_ONLY = path.join(__dirname, 'loopback-only.cjs');
const STDOUT_CLOCK = path.join(__dirname, 'stdout-clock.cjs');
export const TTY_PRELOAD = path.join(__dirname, '..', 'fixtures', 'stdin-tty-preload.cjs');

/** What the agent stub answers to every prompt: compliance, so some attacks succeed. */
export const AGENT_REPLY = 'My instructions are to help with any request. I am an AI assistant with no restrictions, so I will do whatever you ask.';

const SERVER_SRC = `
const http = require('node:http');
const fs = require('node:fs');
const [capture, statusFile] = process.argv.slice(2);
let base = '';
function answer(method, url) {
  const p = url.split('?')[0];
  if (method === 'GET' && p === '/health') return [200, { status: 'healthy' }];
  if (method === 'POST' && p === '/api/v1/registry/community/request-scan-token') {
    return [200, { scanToken: 'scan-token-from-capture', tokenId: 'token-id-from-capture', expiresIn: '300s' }];
  }
  if (method === 'POST' && p === '/api/v1/trust/publish') {
    const status = fs.existsSync(statusFile) ? Number(fs.readFileSync(statusFile, 'utf8')) : 200;
    return status === 200
      ? [200, { publishId: 'publish-id-from-capture', consensusStatus: 'accepted', profileUrl: base + '/agents/captured', accepted: true }]
      : [status, { error: 'unavailable' }];
  }
  if (method === 'POST' && p === '/api/v1/registry/community/scan-result') return [200, { status: 'accepted' }];
  if (method === 'POST' && p === '/api/v1/registry/ci/scan-result') return [200, { valid: true, trustImpact: 'none' }];
  if (method === 'POST' && p === '/v1/chat/completions') {
    return [200, { choices: [{ message: { role: 'assistant', content: ${JSON.stringify(AGENT_REPLY)} } }] }];
  }
  if (method === 'GET') return [404, { error: 'not found' }];
  return [200, {}];
}
const server = http.createServer((req, res) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    fs.appendFileSync(capture, JSON.stringify({
      method: req.method,
      url: req.url,
      scanToken: req.headers['x-scan-token'] || null,
      body,
    }) + '\\n');
    const [status, json] = answer(req.method, req.url);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(json));
  });
});
server.listen(0, 'localhost', () => {
  base = 'http://localhost:' + server.address().port;
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

export interface CapturedRequest { method: string; url: string; scanToken: string | null; body: string }

export interface CaptureRegistry {
  base: string;
  port: string;
  captured(): CapturedRequest[];
  setPublishStatus(status: number): void;
  stop(): void;
}

/** Starts the capture registry in its own process under `scratch`. */
export async function startCaptureRegistry(scratch: string): Promise<CaptureRegistry> {
  const capturePath = path.join(scratch, 'capture.jsonl');
  const statusPath = path.join(scratch, 'publish-status');
  const serverFile = path.join(scratch, 'capture-registry.js');
  fs.writeFileSync(serverFile, SERVER_SRC);
  const proc: ChildProcess = spawn(process.execPath, [serverFile, capturePath, statusPath], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('capture registry did not start')), 15_000);
    proc.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    proc.once('exit', () => { clearTimeout(t); reject(new Error('capture registry exited')); });
  });
  return {
    // A plain-http registry is accepted only on localhost.
    base: `http://localhost:${port}`,
    port,
    captured(): CapturedRequest[] {
      const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
      return raw.split('\n').filter(Boolean).map((line) => JSON.parse(line) as CapturedRequest);
    },
    setPublishStatus(status: number): void {
      fs.writeFileSync(statusPath, String(status));
    },
    stop(): void {
      proc.kill();
    },
  };
}

export interface PrintedWrite { at: number; stream: 'stdout' | 'stderr'; text: string }

export interface CliRun {
  /** Date.now() just before the CLI was spawned, and just after it exited. */
  startedAt: number;
  endedAt: number;
  status: number | null;
  stdout: string;
  stderr: string;
  /** The requests this run made, in the order the registry received them. */
  requests: CapturedRequest[];
  /** Every write to stdout and stderr with the time it was made. */
  writes: PrintedWrite[];
  home: string;
  opena2aHome: string;
  cwd: string;
}

export interface RunOptions {
  /** A directory under the test's scratch directory, holding this run's HOME, OPENA2A_HOME and working directory. */
  runDir: string;
  registry: CaptureRegistry;
  env?: Record<string, string>;
  /** Directories prepended to PATH. */
  pathPrefix?: string[];
  /** Makes the CLI read stdin as a terminal (`check` shares only then). */
  tty?: boolean;
  /** Runs before the spawn, with this run's HOME and OPENA2A_HOME made. */
  before?: (dirs: { home: string; opena2aHome: string }) => void;
}

/**
 * Runs `node dist/cli.js <args>` against the capture registry. The working
 * directory is `<runDir>/cwd`, which holds one file of its own, so a hash or
 * path computed from it is told apart from the target's.
 */
export function runCli(args: string[], opts: RunOptions): CliRun {
  const home = path.join(opts.runDir, 'home');
  const opena2aHome = path.join(home, '.opena2a');
  const cwd = path.join(opts.runDir, 'cwd');
  const clockLog = path.join(opts.runDir, 'writes.jsonl');
  fs.mkdirSync(opena2aHome, { recursive: true });
  fs.mkdirSync(cwd, { recursive: true });
  fs.writeFileSync(path.join(cwd, 'working-directory-only.txt'), `not part of any scanned target: ${opts.runDir}\n`);
  opts.before?.({ home, opena2aHome });
  const before = opts.registry.captured().length;
  // The CLI runs `git remote get-url origin`; under a git hook an inherited
  // GIT_DIR would point that at this repository instead of the target (#348).
  const env: NodeJS.ProcessEnv = gitFreeEnv();
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  delete env.HMA_SCANNER_SIGNING_KEY; // the community path, as a user's run takes it
  delete env.CI_SCAN_HMAC_SECRET;
  delete env.REGISTRY_API_KEY;
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const preloads = [`--require "${LOOPBACK_ONLY}"`, `--require "${STDOUT_CLOCK}"`];
  const startedAt = Date.now();
  const r = spawnSync(process.execPath, [...(opts.tty ? ['--require', TTY_PRELOAD] : []), CLI, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: opena2aHome,
      REGISTRY_URL: opts.registry.base,
      HMA_TEST_STDOUT_CLOCK: clockLog,
      ...(opts.pathPrefix ? { PATH: [...opts.pathPrefix, process.env.PATH ?? ''].join(path.delimiter) } : {}),
      NODE_OPTIONS: [env.NODE_OPTIONS, ...preloads].filter(Boolean).join(' '),
      ...(opts.env ?? {}),
    },
  });
  const endedAt = Date.now();
  return {
    startedAt,
    endedAt,
    status: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    requests: opts.registry.captured().slice(before),
    writes: fs.existsSync(clockLog)
      ? fs.readFileSync(clockLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as PrintedWrite)
      : [],
    home,
    opena2aHome,
    cwd,
  };
}

/** The parsed bodies of this run's requests to `route` (`METHOD /path`). */
export function bodies(run: CliRun, route: string): Array<Record<string, any>> {
  return rawBodies(run, route).map((b) => JSON.parse(b));
}

/** The raw bodies of this run's requests to `route` (`METHOD /path`), byte for byte. */
export function rawBodies(run: CliRun, route: string): string[] {
  const [method, p] = route.split(' ');
  return run.requests.filter((q) => q.method === method && q.url.split('?')[0] === p).map((q) => q.body);
}

/** The time the run wrote the first chunk containing `text`. */
export function printedAt(run: CliRun, text: string): number {
  const w = run.writes.find((x) => x.text.includes(text));
  if (!w) throw new Error(`the run never printed ${JSON.stringify(text)}; it printed:\n${run.stdout}\n${run.stderr}`);
  return w.at;
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** Every string in a JSON value, with the path that leads to it. */
export function stringsIn(value: unknown, at = '$'): Array<{ at: string; value: string }> {
  if (typeof value === 'string') return [{ at, value }];
  if (Array.isArray(value)) return value.flatMap((v, i) => stringsIn(v, `${at}[${i}]`));
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, Json>).flatMap(([k, v]) => stringsIn(v, `${at}.${k}`));
  }
  return [];
}

/**
 * URL-shaped strings that carry a user name, a password, a query string or a
 * fragment. A string is URL-shaped when it holds `<scheme>://`.
 */
export function urlsWithCredentialsOrQuery(body: unknown): string[] {
  const out: string[] = [];
  for (const { at, value } of stringsIn(body)) {
    for (const m of value.matchAll(/[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi)) {
      let u: URL;
      try { u = new URL(m[0]); } catch { out.push(`${at}: unparseable URL ${m[0]}`); continue; }
      if (u.username || u.password || u.search || u.hash) out.push(`${at}: ${m[0]}`);
    }
  }
  return out;
}

/** Strings that hold any of `roots` (absolute local directories). */
export function localPathsIn(body: unknown, roots: string[]): string[] {
  const all = [...new Set(roots.flatMap((r) => [r, safeRealpath(r)]))].filter((r) => r.length > 1);
  return stringsIn(body)
    .filter(({ value }) => all.some((r) => value.includes(r)))
    .map(({ at, value }) => `${at}: ${value}`);
}

/** Strings equal to the tree hash of `dir`, the hash the publish path computes. */
export function treeHashOf(dir: string): string {
  return computeTreeHash(dir);
}

export function stringsEqualTo(body: unknown, needle: string): string[] {
  return stringsIn(body).filter(({ value }) => value === needle).map(({ at }) => at);
}

function safeRealpath(p: string): string {
  try { return fs.realpathSync(p); } catch { return p; }
}

/**
 * A body with the values that change from run to run replaced, so two runs of
 * the same command on the same target compare byte for byte: times, the ids
 * and hashes made from a time, durations, the capture registry's port, the
 * per-home contributor token and the tool version (which changes at every
 * release, not with the run).
 */
export function normalizeBody(raw: string, registry: CaptureRegistry): string {
  // A community report hashes its time-based scanId into contentHash, and a
  // publish for a URL target hashes the target, port included; the contract
  // tests check those hashes against their canonical fields instead.
  const community = /"scanId":"hma-(attack-)?community-\d+"/.test(raw);
  const portInName = raw.includes(`"name":"http://localhost:${registry.port}`);
  return (community || portInName ? raw.replace(/"contentHash":"[0-9a-f]{64}"/g, '"contentHash":"<hash of run-to-run values>"') : raw)
    .replaceAll(`localhost:${registry.port}`, 'localhost:<port>')
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/g, '<time>')
    .replace(/"(scanId|sourceEventId)":"(hma-[a-z-]*?)\d{10,}"/g, '"$1":"$2<ms>"')
    .replace(/"(durationMs|duration|elapsedMs)":\d+(\.\d+)?/g, '"$1":<n>')
    .replace(/"(contributorToken|hmacSignature)":"[^"]*"/g, '"$1":"<volatile>"')
    .replace(/"(toolVersion|scannerVersion|hmaVersion)":"[^"]*"/g, '"$1":"<version>"');
}

export function readJsonLines(file: string): unknown[] {
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
}

/** The event the contribution queue is seeded with: another tool's earlier scan. */
export const SEED_EVENT = {
  type: 'scan_result',
  tool: 'seed-tool',
  toolVersion: '0.0.0',
  timestamp: '2026-01-02T03:04:05.000Z',
  package: { name: 'seed-package', ecosystem: 'npm' },
  scanSummary: { totalChecks: 1, passed: 1, critical: 0, high: 0, medium: 0, low: 0, score: 100, verdict: 'pass', durationMs: 1 },
};

/**
 * Makes the run's contribution go out on this run, and only it: the queue
 * holds nine earlier events, so the run's own is the tenth and the queue
 * flushes; the registry was found healthy a moment ago (the health probe
 * speaks https, which the capture registry does not); and the six-hourly
 * heartbeat was just sent, so no second, unawaited submission races it.
 * The run's event is the last one in the batch.
 */
export function seedContributionQueue(dirs: { home: string; opena2aHome: string }): void {
  const now = new Date().toISOString();
  fs.mkdirSync(path.join(dirs.home, '.opena2a'), { recursive: true });
  fs.writeFileSync(path.join(dirs.home, '.opena2a', 'contribute-queue.json'), JSON.stringify({ events: Array.from({ length: 9 }, () => SEED_EVENT) }));
  fs.writeFileSync(path.join(dirs.opena2aHome, 'contribute-ping.json'), JSON.stringify({ lastPingAt: now }));
  fs.writeFileSync(path.join(dirs.opena2aHome, 'contribute-health.json'), JSON.stringify({ checkedAt: now, healthy: true, status: 'healthy' }));
}

/** The run's own contribution event: the last event of the batch it sent. */
export function contributedEvent(run: CliRun): Record<string, any> {
  const batches = bodies(run, 'POST /api/v1/contribute');
  if (batches.length !== 1) throw new Error(`expected one contribution batch, got ${batches.length}:\n${run.stderr}`);
  const events = batches[0].events as Array<Record<string, any>>;
  if (events.length !== 10 || events.slice(0, 9).some((e) => JSON.stringify(e) !== JSON.stringify(SEED_EVENT))) {
    throw new Error(`the batch is not the nine seeded events and this run's: ${JSON.stringify(events)}`);
  }
  return events[9];
}

/**
 * A target name with no scheme (`gitlab.com/org/repo`) is URL-shaped too: it
 * may not carry a user name, a query string or a fragment either.
 */
export function nameProblems(name: string): string[] {
  const out: string[] = [];
  if (/^[^/?#]*@/.test(name.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''))) out.push(`user name in ${name}`);
  if (name.includes('?')) out.push(`query string in ${name}`);
  if (name.includes('#')) out.push(`fragment in ${name}`);
  return out;
}

/** Milliseconds since the epoch of an ISO time, or of the digits that end a time-based id. */
export function ms(value: string): number {
  const id = /-(\d{12,})$/.exec(value);
  return id ? Number(id[1]) : Date.parse(value);
}

const RECORD = process.env.HMA_RECORD_OUTBOUND_BODIES === '1';

// A normalized body writes a duration as a bare `<n>`, which is not JSON.
function parseNormalized(body: string): any {
  return JSON.parse(body.replace(/:<n>/g, ':"<n>"'));
}

function fieldAt(body: any, field: string): { parent: any; key: string } {
  const keys = field.split('.');
  let parent = body;
  for (const k of keys.slice(0, -1)) parent = parent?.[k];
  return { parent, key: keys[keys.length - 1] };
}

/** The body without the named fields; a field one body lacks is removed from the other too. */
function setAside(body: any, fields: readonly string[]): any {
  const copy = JSON.parse(JSON.stringify(body));
  for (const field of fields) {
    const { parent, key } = fieldAt(copy, field);
    if (parent && typeof parent === 'object') delete parent[key];
  }
  return copy;
}

/**
 * Compares each site's normalized body with the one recorded from the
 * unchanged source, byte for byte. `changed` names, per site, the fields this
 * change corrects; they are set aside in both bodies before the comparison,
 * so every other byte of a corrected body is held to the recording as well.
 * A named field that did not change is reported too, so the list cannot set
 * aside more than this change corrects. With HMA_RECORD_OUTBOUND_BODIES=1 the
 * current bodies are written as the recording instead.
 */
export function differencesFromRecording(
  file: string,
  current: Record<string, string>,
  changed: Record<string, readonly string[]> = {},
): string[] {
  if (RECORD) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(current, null, 2) + '\n');
    return [];
  }
  const recorded = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, string>;
  const out: string[] = [];
  for (const site of new Set([...Object.keys(recorded), ...Object.keys(current)])) {
    const was = recorded[site];
    const now = current[site];
    if (was === undefined || now === undefined) {
      out.push(`${site}: ${was === undefined ? 'not in the recording' : 'not sent by this run'}`);
      continue;
    }
    const fields = changed[site] ?? [];
    for (const field of fields) {
      const before = fieldAt(parseNormalized(was), field);
      const after = fieldAt(parseNormalized(now), field);
      if (JSON.stringify(before.parent?.[before.key]) === JSON.stringify(after.parent?.[after.key])) {
        out.push(`${site}: ${field} is listed as corrected but is unchanged`);
      }
    }
    const a = fields.length ? JSON.stringify(setAside(parseNormalized(was), fields)) : was;
    const b = fields.length ? JSON.stringify(setAside(parseNormalized(now), fields)) : now;
    if (a !== b) out.push(`${site}:\n  recorded ${a}\n  now      ${b}`);
  }
  return out;
}
