/**
 * #1080 — the corpus release harness refuses a corpus that is not a git clone.
 *
 * The goldens under the corpus are recorded against a git clone: GIT-003 asks
 * `git check-ignore` whether a fixture's `.env` is committable and falls back
 * to a heuristic outside a git work tree. Pointed at a `git archive` export of
 * the same corpus commit, `scripts/release-smoke-corpus.ts` printed
 * `FAIL repo/malicious/kitchen-sink` / `golden mismatch` and exited 1, which
 * reads as scoring drift. It now exits 2 with a message naming the clone
 * requirement before it scans anything.
 *
 * Each case builds a synthetic corpus whose one consumer surface has no
 * directory, so an accepted corpus runs no scan at all.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = resolve(__dirname, '..', '..');
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
const HARNESS = join(REPO_ROOT, 'scripts', 'release-smoke-corpus.ts');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const CLONE_HINT = 'clone it: git clone https://github.com/opena2a-org/opena2a-corpus.git <dir>';

function writeCorpus(root: string): void {
  mkdirSync(root, { recursive: true });
  writeFileSync(
    join(root, 'corpus-manifest.yaml'),
    [
      'corpusName: synthetic-1080',
      'corpusVersion: 0.0.0',
      'consumers:',
      '  - name: hackmyagent',
      '    surfaces: [repo]',
      'surfaceIndex: {}',
      '',
    ].join('\n'),
  );
}

/**
 * `ceiling` stops git's upward search there, so a repository above the temp
 * directory cannot answer. The environment is `gitFreeEnv()`: a `GIT_DIR`
 * exported by a git hook would otherwise answer the harness's work-tree
 * question for this repository instead of the corpus.
 */
function runHarness(corpus: string, ceiling: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(TSX, [HARNESS], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: { ...gitFreeEnv(), OPENA2A_CORPUS_PATH: corpus, GIT_CEILING_DIRECTORIES: ceiling, NO_COLOR: '1' },
    timeout: 60_000,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('#1080 release-smoke-corpus refuses a corpus that is not a git clone', () => {
  it('the harness and the built CLI are present', () => {
    expect(existsSync(TSX)).toBe(true);
    expect(existsSync(CLI)).toBe(true);
  });

  it('exits 2 and names the clone requirement for an export with no .git directory', () => {
    const corpus = tempDir('hma-1080-export-');
    writeCorpus(corpus);
    const r = runHarness(corpus, dirname(corpus));
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toContain(`corpus at ${corpus} is not a git clone: it has no .git directory\n`);
    expect(r.stderr).toContain('the goldens are recorded against a git clone');
    expect(r.stderr).toContain(CLONE_HINT);
    expect(r.stdout).not.toContain('passed');
  });

  it('exits 2 for an export extracted inside another git work tree', () => {
    const outer = tempDir('hma-1080-outer-');
    initThrowawayRepo(outer, false);
    const corpus = join(outer, 'corpus');
    writeCorpus(corpus);
    const r = runHarness(corpus, dirname(outer));
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toMatch(
      new RegExp(`corpus at ${corpus.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} is not a git clone: it sits inside the git work tree at \\S+ instead of being a clone of its own\n`),
    );
    expect(r.stderr).toContain(CLONE_HINT);
    expect(r.stdout).not.toContain('passed');
  });

  it('runs a corpus that is the root of its own git work tree', () => {
    const corpus = tempDir('hma-1080-clone-');
    writeCorpus(corpus);
    initThrowawayRepo(corpus, false);
    const r = runHarness(corpus, dirname(corpus));
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stderr).not.toContain('is not a git clone');
    expect(r.stdout).toContain('0 passed, 0 failed, 1 skipped\n');
  });
});
