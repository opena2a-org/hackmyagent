/**
 * #602 — `check`'s URL arm keeps the documented exit-code contract on fetch
 * failure: exit 2 ("does not exist or could not be fetched", the #508 table),
 * never 1, which told a CI consumer "measured, high risk" about a target
 * that was never fetched.
 *
 * RED-ON-BASE: on c9d18b7 all three failure cells exit 1 and `--json` mode
 * writes NOTHING to stdout. Now they settle through `unmeasured(...)` /
 * `settleCheckVerdict` like the npm and local arms: exit 2, the unmeasured
 * banner in text mode, and a coverage document in json mode.
 *
 * The PyPI arm's two sibling sites (no-dist, fetch catch) share the same
 * settlement but have no deterministic offline trigger (the PyPI base URL is
 * hardcoded); they are held by the exit-surface ratchet — their bare exits
 * are GONE from the baseline (the first shrink), so a revert reintroduces a
 * bare site and fails the ratchet, not this file.
 *
 * All fixtures are local: an in-test HTTP server on an ephemeral port, and
 * the discard port for connection refusal. Nothing reaches the network.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, spawn, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

// The fixture server runs in a CHILD process: `spawnSync` blocks this
// worker's event loop for the whole CLI run, so an in-process server could
// never accept the connection (measured as a 120s deadlock on first write).
const SERVER_SRC = `
const http = require('node:http');
const server = http.createServer((req, res) => {
  if (req.url.startsWith('/flaky')) {
    if (req.method === 'HEAD') {
      res.setHeader('content-type', 'application/gzip');
      res.statusCode = 200;
      res.end();
    } else {
      res.statusCode = 500;
      res.end();
    }
    return;
  }
  if (req.url.startsWith('/garbage')) {
    // Answers every request; the body is just not a tarball.
    res.setHeader('content-type', 'application/gzip');
    res.statusCode = 200;
    res.end(req.method === 'HEAD' ? undefined : 'this is not a gzip archive');
    return;
  }
  res.statusCode = 404;
  res.end();
});
server.listen(0, '127.0.0.1', () => {
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

let serverProc: ChildProcess;
let base = '';

beforeAll(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-602-srv-'));
  const file = path.join(dir, 'server.js');
  fs.writeFileSync(file, SERVER_SRC);
  serverProc = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('fixture server did not start')), 10_000);
    serverProc.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    serverProc.once('exit', () => { clearTimeout(t); reject(new Error('fixture server exited')); });
  });
  base = `http://127.0.0.1:${port}`;
});

afterAll(() => {
  serverProc?.kill();
});

function run(target: string, json: boolean) {
  const args = [CLI, 'check', target, '--offline', ...(json ? ['--json'] : [])];
  const r = spawnSync(process.execPath, args, {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-602-home-')) },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function coverage(stdout: string): any {
  const doc = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1));
  return doc.coverage;
}

describe('#602 check URL fetch failures are unmeasured, exit 2', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: HTTP 404 on HEAD → exit 2, target-not-found, a json document exists', () => {
    const r = run(`${base}/missing/pkg.tar.gz`, true);
    expect(r.status, r.stderr).toBe(2);
    const c = coverage(r.stdout);
    expect(c.measured).toBe(false);
    expect(c.reason).toBe('target-not-found');
  });

  it('RED-ON-BASE: download failing after a good HEAD → exit 2, target-unreachable', () => {
    const r = run(`${base}/flaky/pkg.tar.gz`, true);
    expect(r.status, r.stderr).toBe(2);
    const c = coverage(r.stdout);
    expect(c.measured).toBe(false);
    expect(c.reason).toBe('target-unreachable');
  });

  it('RED-ON-BASE: connection refused → exit 2 with the unmeasured banner in text mode', () => {
    // The discard port refuses instantly, so the fetch throws into the URL
    // arm's catch — the site that used to exit 1 with only an error line.
    const r = run('http://127.0.0.1:9/pkg.tar.gz', false);
    expect(r.status, r.stderr).toBe(2);
    expect(r.stderr).toMatch(/not measured|Not measured/i);
  });

  it('a target that answered every request is not called unreachable — bad bytes are no-response, and the wire detail carries no raw message', () => {
    // Adversarial round 2 measured the arm-wide catch claiming "could not
    // be fetched" / target-unreachable for a 200-everything server whose
    // body simply is not an archive — false on both machine-readable
    // claims — and embedding the raw error (with local temp paths) in the
    // persistent detail. The fetched-stage flag decides the claim now.
    const r = run(`${base}/garbage/pkg.tar.gz`, true);
    expect(r.status, r.stderr).toBe(2);
    const c = coverage(r.stdout);
    expect(c.measured).toBe(false);
    expect(c.reason).toBe('no-response');
    expect(c.detail).not.toMatch(/hma-check-url|\/tmp\/|\/var\/folders|Command failed/);
  });

  it("the wire reason cannot be steered by '128' in the URL itself", () => {
    // Round 2's exact repro pair: the old substring sniff mapped ANY
    // message containing "128" to target-not-found, so two identical
    // connection refusals disagreed based on the repo NAME. The reason is
    // structured-evidence-only now: same failure, same reason, whatever
    // the path spells.
    const a = run('http://127.0.0.1:9/repo128.git', true);
    const b = run('http://127.0.0.1:9/repoxyz.git', true);
    expect(a.status, a.stderr).toBe(2);
    expect(b.status, b.stderr).toBe(2);
    expect(coverage(a.stdout).reason).toBe(coverage(b.stdout).reason);
    expect(coverage(a.stdout).reason).toBe('target-unreachable');
  });

  it('PIN: the --help table and the behavior agree on exit 2', () => {
    const r = spawnSync(process.execPath, [CLI, 'check', '--help'], {
      encoding: 'utf8',
      timeout: 60_000,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-602-help-')) },
    });
    expect(r.stdout + r.stderr).toMatch(/2.*(not exist|could not be fetched|not measured)/i);
  });
});
