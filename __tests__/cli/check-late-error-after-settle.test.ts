/**
 * #658 — an error thrown AFTER `check` settled a verdict must not re-settle
 * the run as unmeasured.
 *
 * The remote arms (PyPI, raw URL, GitHub, npm) settle the verdict above the
 * channel branch (#373) and then render. Their catch spans the whole arm, so
 * a throw from the renderer or the post-report pending-scan I/O landed in the
 * fetch-failure handling: the exit raised 1→2 (or 0→2), a "NOT MEASURED"
 * banner printed directly under a fully rendered measured report, and the
 * telemetry event (once-only, already posted at the settle) carried the
 * pre-raise code. After the fix the catch sees the settled verdict, prints the
 * late error plainly, and leaves the settled exit code alone.
 *
 * RED-ON-BASE: on 044301c5 the faulted run exits 2 and prints the
 * NOT MEASURED banner under the report.
 *
 * The raw-URL arm is the one with a deterministic offline trigger: an in-test
 * HTTP server serves a single file, and a preload makes the report renderer's
 * first section header throw. The PyPI, GitHub and npm arms fetch from
 * hardcoded hosts, so the source cells at the bottom hold their guard.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, spawn, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

// Child-process server: spawnSync blocks this worker's event loop, so an
// in-process server could never answer (see check-url-unmeasured-exit.test.ts).
const SERVER_SRC = `
const http = require('node:http');
const server = http.createServer((req, res) => {
  if (req.url.startsWith('/agent.md')) {
    res.setHeader('content-type', 'text/markdown');
    res.statusCode = 200;
    res.end(req.method === 'HEAD' ? undefined : '# Notes agent\\n\\nSummarize the notes the user pastes. Ask before writing any file.\\n');
    return;
  }
  res.statusCode = 404;
  res.end();
});
server.listen(0, '127.0.0.1', () => {
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

const LATE_ERROR = 'injected late render failure';

// Throws once, from the first report section header ("── <label> ──"), which
// displayUnifiedCheck prints only after the verdict has settled.
const PRELOAD_SRC = `
const original = console.log;
let fired = false;
console.log = (...args) => {
  if (!fired && args.map(String).join(' ').includes('\\u2500\\u2500')) {
    fired = true;
    throw new Error(${JSON.stringify(LATE_ERROR)});
  }
  return original(...args);
};
`;

let serverProc: ChildProcess;
let base = '';
let preloadUrl = '';

beforeAll(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-658-srv-'));
  const serverFile = path.join(dir, 'server.js');
  fs.writeFileSync(serverFile, SERVER_SRC);
  const preloadFile = path.join(dir, 'late-throw.mjs');
  fs.writeFileSync(preloadFile, PRELOAD_SRC);
  preloadUrl = pathToFileURL(preloadFile).href;
  serverProc = spawn(process.execPath, [serverFile], { stdio: ['ignore', 'pipe', 'ignore'] });
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

function run(target: string, faulted: boolean) {
  const args = [...(faulted ? ['--import', preloadUrl] : []), CLI, 'check', target, '--offline'];
  const r = spawnSync(process.execPath, args, {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-658-home-')) },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('#658 a late error after a settled check verdict', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: keeps the settled exit code and prints no unmeasured banner', () => {
    const reference = run(`${base}/agent.md`, false);
    // Non-vacuous: the unfaulted run measured the file and rendered a report,
    // so the faulted run's throw really lands after the settle.
    expect(reference.status, reference.stderr).not.toBe(2);
    expect(reference.stdout).toContain('──');
    expect(reference.stderr).not.toContain('NOT MEASURED');

    const faulted = run(`${base}/agent.md`, true);
    expect(faulted.stderr).toContain(LATE_ERROR);
    expect(faulted.status, faulted.stderr).toBe(reference.status);
    expect(faulted.stderr).not.toContain('NOT MEASURED');
    // The late error is not relabelled as a fetch or clone failure.
    expect(faulted.stderr).not.toContain('Error scanning URL');
    expect(faulted.stderr).not.toContain('Could not clone');
  });
});

describe('#658 every remote check arm guards its catch on the settled verdict', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');

  function body(name: string): string {
    const start = src.indexOf(`async function ${name}(`);
    expect(start, `${name} not found in src/cli.ts`).toBeGreaterThan(-1);
    const next = src.indexOf('\nasync function ', start + 1);
    return src.slice(start, next === -1 ? undefined : next);
  }

  for (const arm of ['checkGitHubRepo', 'checkPyPiPackage', 'checkRawUrl', 'checkNpmPackage']) {
    it(`${arm}: every settle inside the try records the verdict, and the catch reads it first`, () => {
      const fn = body(arm);
      const tryStart = fn.indexOf('\n  try {');
      const catchStart = fn.indexOf('\n  } catch (err: unknown) {');
      expect(tryStart).toBeGreaterThan(-1);
      expect(catchStart).toBeGreaterThan(tryStart);

      const tryBody = fn.slice(tryStart, catchStart);
      const settles = tryBody.match(/await settleCheckVerdict\((\w+)\);/g) ?? [];
      expect(settles.length).toBeGreaterThan(0);
      const recorded = tryBody.match(/await settleCheckVerdict\((\w+)\);\s*\n\s*settled = \1;/g) ?? [];
      expect(recorded.length).toBe(settles.length);

      // The PyPI catch opens with a comment block, so the window is wider than the guard.
      const catchHead = fn.slice(catchStart).split('\n').slice(1, 14).join('\n');
      expect(catchHead).toMatch(/rethrowIfRedactionProvenance\(err\);\s*\n\s*if \(settled\) \{\s*\n\s*reportErrorAfterSettledVerdict\(err, settled\);\s*\n\s*return;/);
    });
  }
});
