/**
 * #479 — `secure --deep` must not report a pass when Layer 3 could not run AT
 * ALL. #462 covered a reply that could not be read; a run with no
 * `ANTHROPIC_API_KEY` skipped the layer before any call, and a failure outside
 * the per-file loop was swallowed by an empty catch. Both scored and exited
 * exactly like a deep scan whose analyst found nothing, with nothing on any
 * output channel saying the layer never ran.
 *
 * The ruled shape: ONE `SEM-LLM-NOT-ANALYZED` record for the run (medium,
 * `passed: false`), naming the cause and how many files Layer 3 would have
 * analyzed, so the run exits 2 — unless a critical or high finding already
 * exits it 1, which keeps its precedence.
 *
 * Spawned, like #462's suite, because the claim is an exit code.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, realpathSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { projectKey } from '../../src/store/project-store';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, '..', 'fixtures', 'stub-analyst-preload.cjs');
const FIX_LINE = 'Set ANTHROPIC_API_KEY and re-run with --deep, or drop --deep for the static and semantic result';

/**
 * The issue's fixture: a plaintext admin password and an internal token. The
 * token is assembled at runtime (the token-shape guard's idiom); the bytes on
 * disk are the issue's.
 */
const ISSUE_FIXTURE = `{\n  "adminPassword": "hunter2-real-admin-pw",\n  "internalToken": "${['sk', '-internal-9f3a2b7c1d4e'].join('')}"\n}\n`;
/**
 * A file no static or semantic check flags at critical or high, so the exit
 * code is decided by the deep-scan floor alone. The issue's own fixture now
 * also trips AST-CRED-003 (high), which exits 1 before the floor is read.
 */
const quietFixture = (marker: string) =>
  `{\n  "service": "billing-${marker}",\n  "operatorNote": "the standing office phrase is Wintermute twenty twenty six"\n}\n`;

interface Run { code: number; stdout: string; stderr: string; notRun: any[]; storeKey: string; stored: string[] }

/** Every file under `dir`, as `/`-separated paths relative to it; none when it is absent. */
function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => path.relative(dir, path.join(e.parentPath, e.name)).split(path.sep).join('/'))
    .sort();
}

function runSecure(content: string | null, args: string[], env: Record<string, string> = {}): Run {
  // The scanned tree and the run's user store sit side by side in one
  // directory that is removed when the test ends. Layer 3 keeps its cache and
  // budget record in `$OPENA2A_HOME/projects/<key>/llm-cache`, keyed by the
  // scanned tree, and the default root is ~/.opena2a, so a run without its own
  // OPENA2A_HOME writes that state under the developer's home (#1106).
  const fixture = tempDir('hma-479-');
  const dir = path.join(fixture, 'tree');
  const opena2aHome = path.join(fixture, 'opena2a-home');
  mkdirSync(dir);
  try {
    // `mcp.json` and not `config.json`: Layer 3 never sends a config file and
    // does not count one among the files it would have analyzed.
    if (content !== null) writeFileSync(path.join(dir, 'mcp.json'), content);
    const storeKey = projectKey(realpathSync.native(dir));
    // The key and any preload the parent carries are removed, so "no key"
    // means no key whatever the machine running the suite has set.
    const {
      ANTHROPIC_API_KEY: _key, NODE_OPTIONS: _opts, HMA_STUB_ANALYST_RESPONSE: _r, HMA_STUB_ANALYST_MESSAGE: _m,
      HMA_STUB_ANALYST_THROW: _t, ...base
    } = process.env;
    const res = spawnSync(process.execPath, [CLI, 'secure', '.', ...args, '--json'], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...base, OPENA2A_HOME: opena2aHome, ...env },
    });
    const stdout = res.stdout ?? '';
    const payload = JSON.parse(stdout.slice(stdout.indexOf('{')));
    const notRun = (payload.findings ?? []).filter((f: any) => f.checkId === 'SEM-LLM-NOT-ANALYZED');
    return {
      code: res.status ?? -1,
      stdout,
      stderr: res.stderr ?? '',
      notRun,
      storeKey,
      stored: filesUnder(path.join(opena2aHome, 'projects', storeKey)),
    };
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

beforeAll(assertDistFreshIfPresent);

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build`');
  if (!existsSync(PRELOAD)) throw new Error(`stub preload missing at ${PRELOAD}`);
});

describe('#479 a deep scan whose Layer 3 could not run cannot report a pass', () => {
  it('no key: reports the gap once, says why and how many files, and exits 2', () => {
    const run = runSecure(quietFixture('nokey'), ['--deep']);
    expect(run.notRun).toHaveLength(1);
    const [record] = run.notRun;
    expect(record.severity).toBe('medium');
    expect(record.passed).toBe(false);
    expect(record.message).toContain('ANTHROPIC_API_KEY is not set');
    expect(record.message).toContain('1 file it would have analyzed was not analyzed');
    expect(record.fix).toBe(FIX_LINE);
    expect(run.stderr).toContain(FIX_LINE);
    expect(run.code).toBe(2);
  });

  it('no key, --scan-depth deep: the same record and exit 2', () => {
    const run = runSecure(quietFixture('depth'), ['--scan-depth', 'deep']);
    expect(run.notRun).toHaveLength(1);
    expect(run.code).toBe(2);
  });

  it('no key on the issue fixture: the record is in --json; the high finding still exits 1 first', () => {
    const run = runSecure(ISSUE_FIXTURE, ['--deep']);
    expect(run.notRun).toHaveLength(1);
    expect(run.stderr).toContain(FIX_LINE);
    expect(run.code).toBe(1);
  });

  it('the Layer 3 call throws: the run reaches no deep-scan verdict and exits 2', () => {
    const run = runSecure(quietFixture('throws'), ['--deep'], {
      ANTHROPIC_API_KEY: 'stub-key-never-used-the-preload-answers',
      HMA_STUB_ANALYST_THROW: '1',
      NODE_OPTIONS: `--require ${PRELOAD}`,
    });
    expect(run.notRun.length).toBeGreaterThan(0);
    expect(run.code).toBe(2);
  });

  it('with a stubbed key the issue fixture stays 69/100, exit 1, and carries no gap', () => {
    const run = runSecure(ISSUE_FIXTURE, ['--deep'], {
      ANTHROPIC_API_KEY: 'stub-key-never-used-the-preload-answers',
      HMA_STUB_ANALYST_MESSAGE: JSON.stringify({
        content: [{
          type: 'tool_use',
          id: 'toolu_stub',
          name: 'report_findings',
          input: {
            findings: [
              { line: 2, type: 'Password', severity: 'critical', description: 'admin password', rationale: 'plaintext' },
            ],
          },
        }],
        stop_reason: 'tool_use',
      }),
      NODE_OPTIONS: `--require ${PRELOAD}`,
    });
    expect(run.notRun).toHaveLength(0);
    expect(JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))).score).toBe(69);
    expect(run.code).toBe(1);
  });
});

describe('#479 false-positive controls', () => {
  it('no key and no --deep: no record, exit 0, as before', () => {
    const run = runSecure(quietFixture('nodeep'), []);
    expect(run.notRun).toHaveLength(0);
    expect(run.stderr).not.toContain(FIX_LINE);
    expect(run.code).toBe(0);
  });

  it('no key and no --deep on the issue fixture: no record', () => {
    const run = runSecure(ISSUE_FIXTURE, []);
    expect(run.notRun).toHaveLength(0);
  });

  it('no key, --deep, and nothing for Layer 3 to analyze: no record, exit 0', () => {
    const run = runSecure(null, ['--deep']);
    expect(run.notRun).toHaveLength(0);
    expect(run.stderr).not.toContain(FIX_LINE);
    expect(run.code).toBe(0);
  });
});

describe('#1106 a run of this suite leaves nothing in the home directory', () => {
  it("keeps Layer 3's budget record in the run's own store and none in ~/.opena2a", () => {
    const run = runSecure(quietFixture('ownstore'), ['--deep'], {
      ANTHROPIC_API_KEY: 'stub-key-never-used-the-preload-answers',
      HMA_STUB_ANALYST_MESSAGE: JSON.stringify({
        content: [{ type: 'tool_use', id: 'toolu_stub', name: 'report_findings', input: { findings: [] } }],
        stop_reason: 'tool_use',
      }),
      NODE_OPTIONS: `--require ${PRELOAD}`,
    });
    // Non-vacuity: the run did write Layer 3 state, and it went to the store
    // this file gave it.
    expect(run.stored, "Layer 3 wrote nothing in the run's own store").toContain('llm-cache/budget.json');
    expect(
      existsSync(path.join(homedir(), '.opena2a', 'projects', run.storeKey)),
      'the run wrote a store for its fixture under ~/.opena2a/projects',
    ).toBe(false);
  });
});
