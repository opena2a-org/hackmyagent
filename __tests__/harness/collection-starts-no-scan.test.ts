/**
 * #909 — collecting the suite starts no scan and makes no request.
 *
 * vitest runs every describe body, and everything at module scope, while it
 * collects a file. That includes `vitest list`, which runs no test. A scan
 * written there runs on every collection, ahead of the file's own hooks, and
 * under an empty HOME it downloads the classifier model: `npx vitest list`
 * left tokenizer.json, nanomind-tme.onnx and nanomind-tme.onnx.data (8.7 MB)
 * in $HOME/.nanomind/models. All of it came from one describe body, in
 * __tests__/cli/sarif-unique-rules.test.ts.
 *
 * The first cell collects every suite that names the built CLI in a nested
 * `vitest list`, with two recorders preloaded into each process that run
 * starts. __tests__/helpers/cli-start-recorder.cjs notes each start of the
 * built CLI, and __tests__/helpers/net-recorder.cjs notes each outbound
 * request at the call site, so a request to an unreachable host still counts.
 * Both must stay empty. The selection is the suites that start the CLI, the
 * shape behind this issue: collecting every file costs about a minute of CPU,
 * on every run of the suite.
 *
 * The second cell collects a fixture that starts the CLI and makes a request
 * from its describe body, which shows the recorders reach a collecting
 * worker and the processes it starts. The third does the same with spawns
 * whose `env` replaces process.env, which drops NODE_OPTIONS and the markers:
 * several suites spawn the CLI that way, and the start recorder forwards both
 * into such a spawn (#911).
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { tempDir } from '../helpers/temp-dir';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VITEST = path.join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');
const HELPERS = path.join(REPO_ROOT, '__tests__', 'helpers');
const FIXTURE_CONFIG = path.join(HELPERS, 'collection-fixture', 'vitest.config.ts');
const CLI_START_RECORDER = path.join(HELPERS, 'cli-start-recorder.cjs');
const NET_RECORDER = path.join(HELPERS, 'net-recorder.cjs');

/**
 * The three spellings __tests__/harness/spawn-suites-assert-freshness.test.ts
 * treats as naming the built CLI. A mention inside a comment selects a file
 * too, which costs only that file's collection.
 */
const NAMES_BUILT_CLI = /dist\/cli\.js|['"]dist['"]\s*,\s*['"]cli\.js['"]|\bBUILT_CLI\b/;

/** Every test file the main config collects whose source names the built CLI. */
function suitesNamingTheCli(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && full !== HELPERS) walk(full);
      } else if (entry.name.endsWith('.test.ts') && NAMES_BUILT_CLI.test(readFileSync(full, 'utf8'))) {
        out.push(path.relative(REPO_ROOT, full).split(path.sep).join('/'));
      }
    }
  };
  walk(path.join(REPO_ROOT, '__tests__'));
  walk(path.join(REPO_ROOT, 'src'));
  return out.sort();
}

/** Runs `vitest list` in a fresh process with both recorders preloaded. */
function collect(args: string[]) {
  const markers = tempDir('hma-collect-markers-');
  const cliStarts = path.join(markers, 'cli-starts');
  const requests = path.join(markers, 'requests');
  // The worker's own VITEST_* variables describe this run, not the nested one.
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.startsWith('VITEST')) env[k] = v;
  }
  // A regression must not fetch the model while it is being caught: the
  // download honours these variables, and the recorder notes the attempt
  // before the proxy refuses it. NO_PROXY could send the download direct.
  for (const k of ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY']) delete env[k];
  const preload = [CLI_START_RECORDER, NET_RECORDER].map((f) => `--require ${JSON.stringify(f)}`).join(' ');
  const res = spawnSync(process.execPath, [VITEST, 'list', '--json', '--maxWorkers=2', ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf-8',
    timeout: 150_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      HOME: tempDir('hma-collect-home-'),
      HTTPS_PROXY: 'http://127.0.0.1:9',
      NODE_OPTIONS: [env.NODE_OPTIONS, preload].filter(Boolean).join(' '),
      HMA_TEST_CLI_START_MARKER: cliStarts,
      HMA_TEST_NET_MARKER: requests,
      NO_COLOR: '1',
    },
  });
  const lines = (f: string): string[] =>
    existsSync(f) ? readFileSync(f, 'utf8').split('\n').filter(Boolean) : [];
  let listed: Array<{ file: string }> = [];
  try {
    listed = JSON.parse(res.stdout ?? '');
  } catch {
    // Left empty; the caller's assertions report stderr.
  }
  const files = new Set(listed.map((t) => path.relative(REPO_ROOT, t.file).split(path.sep).join('/')));
  return {
    status: res.status,
    // stdout is the JSON list; what went wrong is on stderr.
    out: `exit ${res.status}${res.signal ? ` (${res.signal})` : ''}\n${(res.stderr ?? '').slice(-4000)}`,
    files,
    cliStarts: lines(cliStarts),
    requests: lines(requests),
  };
}

describe('collecting the suite starts no scan', () => {
  it('collecting every suite that names the built CLI starts no CLI process and makes no request', () => {
    const suites = suitesNamingTheCli();
    // Non-vacuity: a broken walk would collect nothing and record nothing.
    expect(suites.length).toBeGreaterThan(100);
    expect(suites).toContain('__tests__/cli/sarif-unique-rules.test.ts');

    const run = collect(suites);
    expect(
      { cliStarts: run.cliStarts, requests: run.requests },
      'Collecting a file ran a scan or made a request. vitest runs a describe body and module scope\n'
        + 'while it collects, under `vitest list` too; move the work into beforeAll or a test.\n'
        + run.out,
    ).toEqual({ cliStarts: [], requests: [] });
    // A file that throws while it is collected fails the run, and an error
    // can stop a describe body before the work this cell watches for.
    expect(run.status, run.out).toBe(0);
    // Non-vacuity: the nested run collected the selection. Not every file:
    // a `describe.skipIf` whose condition holds is left out of the list.
    expect(run.files.size, run.out).toBeGreaterThan(100);
  });

  it('non-vacuity: a describe body that starts the CLI and makes a request is seen doing both', () => {
    const run = collect(['--config', FIXTURE_CONFIG, 'starts-cli']);
    expect(run.files, run.out).toEqual(new Set(['__tests__/helpers/collection-fixture/starts-cli.fixture.ts']));
    expect(run.cliStarts, run.out).toEqual([JSON.stringify(['--version'])]);
    expect(run.requests, run.out).toContain('127.0.0.1:9');
  });

  it('non-vacuity: a spawn whose env replaces process.env is seen starting the CLI and making a request', () => {
    const run = collect(['--config', FIXTURE_CONFIG, 'replaced-env']);
    expect(run.files, run.out).toEqual(new Set(['__tests__/helpers/collection-fixture/replaced-env.fixture.ts']));
    expect(run.cliStarts, run.out).toEqual([JSON.stringify(['-V'])]);
    expect(run.requests, run.out).toContain('localhost:9');
  });
});
