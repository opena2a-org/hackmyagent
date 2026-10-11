/**
 * #983 — `secure --deep` runs the behavioural simulation whatever the output
 * format, and `--json` carries what it observed.
 *
 * The run was guarded on text output. `secure --deep --json` over a tree where
 * text mode printed `[Simulation] Running behavioral simulation on 1
 * artifact(s)...` printed no simulation line and carried no simulation key, so
 * the flag did less in CI than in a terminal and nothing said so.
 *
 * Spawned, because the claim is about which channel carries what. Every run
 * has `fetch` fail and no API key, so no probe executor is reachable on any
 * machine: the simulation reports NOT MEASURED, which is enough to show it ran.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, '..', 'fixtures', 'stub-analyst-preload.cjs');

const SKILL = '# Notes skill\n\nSummarise the meeting notes the user pastes in.\n';
const RUNNING = '[Simulation] Running behavioral simulation on 1 artifact(s)...';
const NOT_MEASURED_BLOCK = {
  advisory: true,
  status: 'not-measured',
  executor: null,
  artifactsFound: 1,
  artifactsSimulated: 0,
  artifactLimit: 10,
  linksSkipped: 0,
  artifacts: [],
  reason: 'no probe executor (NanoMind daemon, Ollama, or ANTHROPIC_API_KEY)',
};

interface Run { code: number; stdout: string; stderr: string }

/** `secure . <args>` over a tree holding the given files, with no executor reachable. */
function secure(files: Record<string, string>, args: string[]): Run {
  const dir = tempDir('hma-983-');
  for (const [name, content] of Object.entries(files)) writeFileSync(path.join(dir, name), content);
  const {
    ANTHROPIC_API_KEY: _key, OPENAI_API_KEY: _openai, NODE_OPTIONS: _opts, HMA_STUB_ANALYST_RESPONSE: _shape,
    ...base
  } = process.env;
  const res = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'secure', '.', ...args], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...base, NO_COLOR: '1', HMA_STUB_ANALYST_THROW: '1' },
    timeout: 150_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { code: res.status ?? -1, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

beforeAll(assertDistFreshIfPresent);

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build`');
  if (!existsSync(PRELOAD)) throw new Error(`stub preload missing at ${PRELOAD}`);
});

describe('#983 secure --deep runs the simulation in every output format', () => {
  it('--json: the simulation lines are on stderr and stdout is still one JSON document', () => {
    const run = secure({ 'SKILL.md': SKILL }, ['--deep', '--json']);

    expect(run.stderr).toContain(RUNNING);
    expect(run.stderr.match(/NOT MEASURED/g), run.stderr).toHaveLength(1);
    expect(run.stdout).not.toContain('[Simulation]');
    const doc = JSON.parse(run.stdout);
    expect(doc.simulation).toEqual(NOT_MEASURED_BLOCK);
    // Advisory: the block is not a finding and the exit code is the one the
    // document already settled.
    expect(doc.exitCode).toBe(run.code);
    expect(JSON.stringify(doc.findings)).not.toContain('Simulation');
  });

  it.each(['sarif', 'html', 'asff'])('--format %s: the simulation lines are on stderr, not in the document', (format) => {
    const run = secure({ 'SKILL.md': SKILL }, ['--deep', '--format', format]);

    expect(run.stderr).toContain(RUNNING);
    expect(run.stderr.match(/NOT MEASURED/g), run.stderr).toHaveLength(1);
    expect(run.stdout).not.toContain('[Simulation]');
    expect(run.stdout.length).toBeGreaterThan(0);
  });

  it('text: prints the same lines it did before', () => {
    const run = secure({ 'SKILL.md': SKILL }, ['--deep']);

    expect(run.stderr).toContain(RUNNING);
    expect(run.stderr.match(/NOT MEASURED/g), run.stderr).toHaveLength(1);
    expect(run.stderr).toContain('[Simulation] Complete.');
  });

  it('--json over a tree with nothing to simulate says so in the block', () => {
    const run = secure({ 'config.json': '{\n  "service": "billing"\n}\n' }, ['--deep', '--json']);

    expect(run.stderr).toContain('[Simulation] No skill/SOUL/MCP artifacts found. Simulation skipped.');
    const doc = JSON.parse(run.stdout);
    expect(doc.simulation).toEqual({
      ...NOT_MEASURED_BLOCK,
      status: 'no-artifacts',
      artifactsFound: 0,
      reason: undefined,
    });
    expect('reason' in doc.simulation).toBe(false);
  });

  it('without --deep there is no simulation: no line and no block', () => {
    const run = secure({ 'SKILL.md': SKILL }, ['--json']);

    expect(run.stderr).not.toContain('[Simulation]');
    expect('simulation' in JSON.parse(run.stdout)).toBe(false);
  });

  it.each(['oasb-1', 'oasb-2'])('-b %s --json carries the block on the same key', (benchmark) => {
    const run = secure({ 'SKILL.md': SKILL }, ['--deep', '-b', benchmark, '--json']);

    expect(run.stderr).toContain(RUNNING);
    const doc = JSON.parse(run.stdout);
    expect(doc.simulation).toEqual(NOT_MEASURED_BLOCK);
  });
});
