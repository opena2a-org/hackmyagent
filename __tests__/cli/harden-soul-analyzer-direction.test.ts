/**
 * #446 — the analyzers that read a hardened tree agree on its direction.
 *
 * `secure --deep` rated the `SOUL.md` that `harden-soul` writes `MALICIOUS
 * (95% confidence, 14/20 probes failed)` and a three-line README `SUSPICIOUS`,
 * while `scan-soul` rated the same SOUL.md `100/100 HARDENED`. The verdict was
 * a text search over the artifact's own wording, run because no probe executor
 * was present; no probe input was ever sent anywhere. The channel now says
 * `NOT MEASURED` in that case and runs no probe.
 *
 * The CLI is SPAWNED, with both API keys removed from the environment, because
 * the claim is about what a user without an executor sees and about an exit
 * code, and both are only real at a process boundary. If a NanoMind daemon or
 * an Ollama server is reachable on this machine the deep cells measure an
 * executor run instead and the `NOT MEASURED` cell fails loudly rather than
 * passing on the wrong path.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');

const README = '# my-agent\nA small AI agent that proxies chat requests.\n## Run\n    npm start\n';

/** Run one command in the fixture tree with no probe executor in the environment. */
function run(dir: string, args: string[]): { code: number; out: string } {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY;
  delete env.OPENAI_API_KEY;
  const res = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env });
  return { code: res.status ?? -1, out: (res.stdout ?? '') + (res.stderr ?? '') };
}

/** The `Security ... NN/100` line, with the bar characters removed. */
function scoreLine(out: string): string | undefined {
  return out.split('\n').map(l => l.replace(/[━]+/g, '').replace(/\s+/g, ' ').trim())
    .find(l => /^Security \d+\/100$/.test(l));
}

// #285 — this suite spawns the BUILT cli, so a stale `dist` would test the
// previous code and pass.
beforeAll(assertDistFreshIfPresent);

let dir = '';

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build`');
  dir = mkdtempSync(path.join(tmpdir(), 'hma-446-direction-'));
  writeFileSync(path.join(dir, 'README.md'), README);
  const harden = run(dir, ['harden-soul', '.']);
  if (harden.code !== 0 || !existsSync(path.join(dir, 'SOUL.md'))) {
    throw new Error(`harden-soul did not write SOUL.md (exit ${harden.code}):\n${harden.out.slice(0, 800)}`);
  }
});

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe('#446 analyzers agree on the direction of a hardened tree', () => {
  it('precondition: scan-soul rates the generated SOUL.md 100/100', () => {
    const { out } = run(dir, ['scan-soul', '.']);
    expect(out, 'the fixture is not the hardened tree the other cells rely on').toContain('100/100');
  });

  for (const args of [['scan-soul', '.'], ['check', '.', '--nanomind'], ['secure', '.', '--deep']]) {
    it(`${args.join(' ')} prints neither MALICIOUS nor SUSPICIOUS`, () => {
      const { out } = run(dir, args);
      expect(out).not.toContain('MALICIOUS');
      expect(out).not.toContain('SUSPICIOUS');
    });
  }

  it('secure --deep says NOT MEASURED exactly once when no probe executor is present', () => {
    const { out } = run(dir, ['secure', '.', '--deep']);
    const hits = out.match(/NOT MEASURED/g) ?? [];
    expect(hits, `expected one NOT MEASURED line, saw ${hits.length}:\n${out.slice(0, 1200)}`).toHaveLength(1);
    expect(out).toContain('no probe executor');
    // The advisory count is the executor path; with none present it cannot appear.
    expect(out).not.toContain('probes flagged');
  });

  it('secure --deep carries the same score and exit code as secure', () => {
    const deep = run(dir, ['secure', '.', '--deep']);
    const plain = run(dir, ['secure', '.']);
    const deepScore = scoreLine(deep.out);
    const plainScore = scoreLine(plain.out);
    expect(deepScore, `no score line in secure --deep output:\n${deep.out.slice(0, 1200)}`).toBeDefined();
    expect(plainScore, `no score line in secure output:\n${plain.out.slice(0, 1200)}`).toBeDefined();
    expect(deepScore).toBe(plainScore);
    expect(deep.code).toBe(plain.code);
  });
});
