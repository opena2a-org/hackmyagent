/**
 * A test run leaves nothing in the temporary directory.
 *
 * Spawn tests handed the CLI a throwaway HOME made inline with
 * `fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'))` and never removed it.
 * Two CLI test files, run once with an empty TMPDIR, left 28 directories; a
 * host running the suite repeatedly collected more than sixteen thousand and
 * filled its disk.
 *
 * `tempDir` (__tests__/helpers/temp-dir.ts) now creates every such directory
 * and registers its removal. Two cells hold that in place:
 *
 *   - the suite-level cell runs a fixture suite with TMPDIR set to a fresh,
 *     empty directory and asserts the directory is still empty afterwards, with
 *     tests that pass, fail, are cancelled and leave an unreadable entry; a
 *     second run, with a directory created behind the helper, shows the cell
 *     can see a leak at all;
 *   - the source cell fails when a test file calls `mkdtemp` or `mkdtempSync`
 *     itself. Files that predate the helper are frozen in
 *     __tests__/helpers/temp-dir-baseline.ts, and that list only shrinks.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { tempDir } from '../helpers/temp-dir';
import { RAW_MKDTEMP_BASELINE } from '../helpers/temp-dir-baseline';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VITEST = path.join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');
const FIXTURE_CONFIG = path.join(REPO_ROOT, '__tests__', 'helpers', 'temp-dir-fixture', 'vitest.config.ts');
const HELPER = '__tests__/helpers/temp-dir.ts';

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*m/g;

/** Runs the fixture suite in a fresh vitest process with TMPDIR set to `tmp`. */
function runFixture(tmp: string, extraEnv: Record<string, string> = {}) {
  // The worker's own VITEST_* variables describe this run, not the nested one.
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.startsWith('VITEST')) env[k] = v;
  }
  const res = spawnSync(process.execPath, [VITEST, 'run', '--config', FIXTURE_CONFIG], {
    cwd: REPO_ROOT,
    encoding: 'utf-8',
    timeout: 120_000,
    env: { ...env, ...extraEnv, TMPDIR: tmp, NO_COLOR: '1' },
  });
  const out = `${res.stdout ?? ''}${res.stderr ?? ''}`.replace(ANSI, '');
  // The summary line: `Tests  1 failed | 3 passed | 1 skipped (5)`.
  const summary = out.match(/^\s*Tests\s+(.+)$/m)?.[1] ?? '';
  const count = (word: string): number => Number(summary.match(new RegExp(`(\\d+) ${word}`))?.[1] ?? 0);
  return { status: res.status, out, failed: count('failed'), passed: count('passed'), skipped: count('skipped') };
}

describe('a test run leaves nothing in TMPDIR', () => {
  it('the fixture suite leaves an empty TMPDIR empty, whether its tests pass, fail, are cancelled or leave an unreadable entry', () => {
    const tmp = tempDir('hma-tmpdir-cell-');
    const run = runFixture(tmp);
    // The fixture fails exactly one test on purpose; anything else means the
    // fixture's own assertions about early removal did not hold.
    expect(run.out).toContain('FIXTURE-FAILS on purpose');
    expect({ status: run.status, failed: run.failed, passed: run.passed, skipped: run.skipped }).toEqual({
      status: 1,
      failed: 1,
      passed: 3,
      skipped: 1,
    });
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('non-vacuity: a directory created without the helper is still there when the run ends', () => {
    const tmp = tempDir('hma-tmpdir-cell-');
    const run = runFixture(tmp, { HMA_TEMP_DIR_FIXTURE_LEAK: '1' });
    expect({ failed: run.failed, passed: run.passed }).toEqual({ failed: 1, passed: 4 });
    expect(readdirSync(tmp)).toEqual(['fixture-raw-leak']);
  });
});

/** Every file vitest can load as a test or test helper. */
function testSources(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules') walk(full);
        continue;
      }
      const rel = path.relative(REPO_ROOT, full).split(path.sep).join('/');
      const inTests = rel.startsWith('__tests__/') && /\.(ts|js|cjs|mjs)$/.test(rel);
      const inSrc = rel.startsWith('src/') && (rel.endsWith('.test.ts') || rel.includes('/__tests__/'));
      if ((inTests || inSrc) && rel !== HELPER) out.push(rel);
    }
  };
  walk(path.join(REPO_ROOT, '__tests__'));
  walk(path.join(REPO_ROOT, 'src'));
  return out.sort();
}

/**
 * Line numbers of every call to a function named `mkdtemp` or `mkdtempSync`,
 * whether bare (`mkdtempSync(...)`) or through an object (`fs.mkdtempSync`,
 * `fs.promises.mkdtemp`). Parsed, so a mention in a comment or string is not
 * a call.
 */
function mkdtempCalls(rel: string, src = readFileSync(path.join(REPO_ROOT, rel), 'utf-8')): number[] {
  if (!src.includes('mkdtemp')) return [];
  const kind = rel.endsWith('.ts') ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const source = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, kind);
  const lines: number[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const name = ts.isIdentifier(callee)
        ? callee.text
        : ts.isPropertyAccessExpression(callee)
          ? callee.name.text
          : '';
      if (name === 'mkdtemp' || name === 'mkdtempSync') {
        lines.push(source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return lines;
}

describe('temporary directories in tests are made through tempDir', () => {
  it('no test file calls mkdtemp or mkdtempSync outside the helper, beyond the frozen list', () => {
    const actual = new Map<string, number[]>();
    for (const rel of testSources()) {
      const lines = mkdtempCalls(rel);
      if (lines.length > 0) actual.set(rel, lines);
    }
    const problems: string[] = [];
    for (const rel of new Set([...actual.keys(), ...Object.keys(RAW_MKDTEMP_BASELINE)])) {
      const lines = actual.get(rel) ?? [];
      const frozen = RAW_MKDTEMP_BASELINE[rel] ?? 0;
      if (lines.length > frozen) {
        problems.push(
          `${rel}: ${lines.length} mkdtemp call(s), ${frozen} allowed, at line(s) ${lines.join(', ')}; ` +
            `use tempDir() from ${HELPER}, which removes the directory when the test ends`,
        );
      } else if (lines.length < frozen) {
        problems.push(
          `${rel}: ${lines.length} mkdtemp call(s), ${frozen} frozen; lower the entry in ` +
            `__tests__/helpers/temp-dir-baseline.ts (delete it at zero)`,
        );
      }
    }
    expect(problems).toEqual([]);
  });

  it('the source cell counts calls in every form the suite writes them, and nothing else', () => {
    // The parser is the whole cell; one that matched nothing would pass the
    // cell above on any tree.
    const sample = [
      "import { mkdtempSync } from 'node:fs';",
      "const a = fs.mkdtempSync(path.join(os.tmpdir(), 'a-'));",
      "const b = mkdtempSync(join(tmpdir(), 'b-'));",
      "const c = await fsp.mkdtemp(join(tmpdir(), 'c-'));",
      "const d = await fs.promises.mkdtemp(join(tmpdir(), 'd-'));",
      "// a comment naming fs.mkdtempSync(x) is not a call",
      "const e = 'nor is a string naming mkdtempSync(x)';",
    ].join('\n');
    expect(mkdtempCalls('sample.ts', sample)).toEqual([2, 3, 4, 5]);
    expect(mkdtempCalls('sample.cjs', sample.split('\n').slice(1, 3).join('\n'))).toEqual([1, 2]);
    // The helper is the one file allowed to make the call, and makes it once.
    expect(mkdtempCalls(HELPER)).toHaveLength(1);
  });
});
