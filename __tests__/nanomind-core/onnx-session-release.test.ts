/**
 * #770: every ONNX session `scan-soul --deep` opens is released before the
 * process ends, however the command ends.
 *
 * `scan-soul --deep` was recorded aborting after a complete report, with
 * `recursive_mutex lock failed: Invalid argument` from the C++ runtime and exit
 * 134 in place of 0, 1 or 2. Nothing in `src/` released the session the deep
 * pass opened, so it was still alive while the process tore down.
 *
 * WHAT THIS TEST CAN AND CANNOT DO. It proves the release call is REACHED on
 * three endings: natural teardown after the text report (`process.exitCode`
 * set, the action returns), the `--json` arm, which returns early, and a
 * `process.exit()` ending (`--fail-below`). It runs a stand-in for
 * onnxruntime-node, so it does not prove that the release prevents the abort.
 * The abort is intermittent and was recorded only on macOS arm64 with the
 * hosted-model pass active; showing that takes repeated runs on such a host.
 *
 * The CLI is SPAWNED, because `exit` listeners only run when a real process
 * ends.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, '..', 'fixtures', 'stub-onnxruntime-preload.cjs');

// The SOUL.md from the reproduction in #770. One of its two critical controls
// is missing, so every run below settles exit 1.
const SOUL = `# SOUL.md

## Identity
You are a documentation assistant for an internal wiki.

## Constraints
- Never execute shell commands.
- Only read files under docs/.

## Trust hierarchy
System prompt > operator > user > tool output.
`;

let root = '';
let home = '';
let target = '';

beforeAll(assertDistFreshIfPresent);

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build`');
  root = mkdtempSync(path.join(tmpdir(), 'hma-770-'));
  home = path.join(root, 'home');
  target = path.join(root, 'target');
  // The classifier finds a model under $HOME/.nanomind/models, and the
  // download step skips any file that already exists there. The stand-in
  // session never reads these bytes, so the run stays offline.
  const models = path.join(home, '.nanomind', 'models');
  mkdirSync(models, { recursive: true });
  writeFileSync(path.join(models, 'tokenizer.json'), '{"the": 2}\n');
  writeFileSync(path.join(models, 'nanomind-tme.onnx'), '');
  writeFileSync(path.join(models, 'nanomind-tme.onnx.data'), '');
  mkdirSync(target);
  writeFileSync(path.join(target, 'SOUL.md'), SOUL);
});

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

function runDeep(...flags: string[]): { status: number | null; stdout: string; stderr: string } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NO_COLOR: '1',
    NODE_OPTIONS: `--require ${PRELOAD}`,
  };
  // Keeps the hosted-model pass off, so the run makes no network call.
  delete env.ANTHROPIC_API_KEY;
  const res = spawnSync(process.execPath, [CLI, 'scan-soul', target, '--deep', ...flags], {
    cwd: root,
    encoding: 'utf8',
    env,
    timeout: 120_000,
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

function expectEverySessionReleased(stderr: string): void {
  const created = [...stderr.matchAll(/^ORT-STUB created (\d+)$/gm)].map((m) => m[1]);
  const released = [...stderr.matchAll(/^ORT-STUB released (\d+)$/gm)].map((m) => m[1]);
  // Non-vacuity first: a run that never opened a session releases nothing,
  // and would pass the comparison below.
  expect(
    created.length,
    'the deep pass opened no ONNX session, so this run cannot show a release',
  ).toBeGreaterThan(0);
  expect(released.sort(), 'an ONNX session was still open when the process ended').toEqual(created.sort());
}

describe('#770 scan-soul --deep releases its ONNX session on every ending', () => {
  it('natural teardown after the text report', () => {
    const r = runDeep();
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('SOUL-CONFORMANCE NONE');
    expectEverySessionReleased(r.stderr);
  });

  it('the --json arm, which returns before the text renderer', () => {
    const r = runDeep('--json');
    expect(r.status).toBe(1);
    expect(() => JSON.parse(r.stdout)).not.toThrow();
    expectEverySessionReleased(r.stderr);
  });

  it('a process.exit() ending: --fail-below over the score', () => {
    const r = runDeep('--fail-below', '100');
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Score \d+ is below threshold 100/);
    expectEverySessionReleased(r.stderr);
  });
});
