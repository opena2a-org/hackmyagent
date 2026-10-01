/**
 * #285 — every suite that spawns the built CLI must assert the build is fresh.
 *
 * The process note behind this: during the 0.25.1 mutation pass `dist/` was
 * stale for part of the work, so roughly half the new coverage was passing
 * against an older binary. `assertDistFresh` was written for that, and then
 * applied to four suites. Measured while closing #285: **31 of the 35 suites
 * that spawn `dist/cli.js` had no freshness check at all.**
 *
 * That is not a per-suite oversight, it is a missing gate — a new spawn suite
 * arrives with the hole by default. So the question is asked of every suite at
 * once, here, rather than left to whoever writes the next one.
 *
 * This is a static gate on purpose. The failure it prevents is a test that
 * PASSES against code that is no longer under test, which no runtime assertion
 * inside a passing suite can detect.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const TESTS_ROOT = path.resolve(__dirname, '..');

/** Every `.test.ts` under `__tests__/`. */
function allTestFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) allTestFiles(full, out);
    else if (entry.name.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

/**
 * `src` with every comment blanked out, string and regex literals intact.
 *
 * #561 — both predicates below ran over the whole file, so a suite that only
 * MENTIONED `dist/cli.js` in a comment was reported as a spawn suite, and the
 * only way out was to reword the comment (evading the text gate) or to add a
 * freshness check to a suite that never runs the binary (a false statement).
 * The mirror hole closes with it: a comment naming `assertDistFresh` no longer
 * counts as the check. The parser finds the comments, not a regex, because a
 * quote or `//` inside a string or regex literal is not a comment boundary.
 * Blanking keeps offsets and line breaks, so nothing else shifts.
 */
function withoutComments(src: string): string {
  const source = ts.createSourceFile('suite.ts', src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const chars = src.split('');
  const blank = (pos: number, end: number): void => {
    for (let i = pos; i < end; i++) if (chars[i] !== '\n' && chars[i] !== '\r') chars[i] = ' ';
  };
  // Every comment is trivia in front of some token, so reading the leading
  // comment ranges at each token's full start reaches all of them, including
  // the ones before the end-of-file token.
  const visit = (node: ts.Node): void => {
    const children = node.getChildren(source);
    if (children.length === 0) {
      for (const r of ts.getLeadingCommentRanges(src, node.pos) ?? []) blank(r.pos, r.end);
      return;
    }
    children.forEach(visit);
  };
  visit(source);
  return chars.join('');
}

/**
 * A suite spawns the built CLI if its CODE names `dist/cli.js`, however the
 * path is assembled — `'dist/cli.js'`, `join(root, 'dist', 'cli.js')`, or the
 * `BUILT_CLI` export. A mention inside a comment is not a spawn.
 */
function spawnsBuiltCli(src: string): boolean {
  const code = withoutComments(src);
  return (
    /dist\/cli\.js/.test(code)
    || /['"]dist['"]\s*,\s*['"]cli\.js['"]/.test(code)
    || /\bBUILT_CLI\b/.test(code)
  );
}

function assertsFreshness(src: string): boolean {
  return /assertDistFresh(IfPresent)?\b/.test(withoutComments(src));
}

describe('#285 spawn suites assert dist freshness', () => {
  const files = allTestFiles(TESTS_ROOT);

  it('finds the suites at all (the gate is not scanning an empty set)', () => {
    // Non-vacuity. A broken root, a renamed extension, or a bad recursion
    // would make every assertion below trivially true.
    expect(files.length).toBeGreaterThan(150);
    expect(files.filter((f) => spawnsBuiltCli(readFileSync(f, 'utf8'))).length).toBeGreaterThan(20);
  });

  it('every suite that spawns dist/cli.js asserts the build is fresh', () => {
    const offenders = files
      .filter((f) => {
        const src = readFileSync(f, 'utf8');
        return spawnsBuiltCli(src) && !assertsFreshness(src);
      })
      .map((f) => path.relative(TESTS_ROOT, f))
      .sort();

    expect(
      offenders,
      'These suites spawn the built CLI without checking it is newer than src/.\n'
      + 'They would measure the previous binary and report a pass.\n'
      + "Add:  import { assertDistFreshIfPresent } from '<rel>/helpers/dist-freshness';\n"
      + '      beforeAll(assertDistFreshIfPresent);',
    ).toEqual([]);
  });

  it('the detector recognises each way the path is actually written', () => {
    // Guards the gate's own predicate. A detector that missed
    // `join(root, 'dist', 'cli.js')` would report zero offenders forever.
    expect(spawnsBuiltCli(`const CLI = 'dist/cli.js';`)).toBe(true);
    expect(spawnsBuiltCli(`const CLI = join(REPO_ROOT, 'dist', 'cli.js');`)).toBe(true);
    expect(spawnsBuiltCli(`const CLI = join(REPO_ROOT, "dist", "cli.js");`)).toBe(true);
    expect(spawnsBuiltCli(`import { BUILT_CLI } from '../helpers/dist-freshness';`)).toBe(true);
    expect(spawnsBuiltCli(`const x = 'src/cli.ts';`)).toBe(false);

    // #561 — a mention inside a comment is not a spawn, in either comment form,
    // while the same path in code still is, including on the same line.
    expect(spawnsBuiltCli(`// a follow-up spawns dist/cli.js (#560)\nimport { f } from '../../src/ui/x';`)).toBe(false);
    expect(spawnsBuiltCli(`/* drive dist/cli.js with join('dist', 'cli.js') and BUILT_CLI */\nconst y = 1;`)).toBe(false);
    expect(spawnsBuiltCli(`const CLI = 'dist/cli.js'; // spawns dist/cli.js`)).toBe(true);
    // A `//` or quote inside a string or regex literal is not a comment boundary.
    expect(spawnsBuiltCli(`const u = 'https://x'; const CLI = 'dist/cli.js';`)).toBe(true);
    expect(spawnsBuiltCli(`const re = /['"]x\\/\\//; const CLI = join(ROOT, 'dist', 'cli.js');`)).toBe(true);
    // And the mirror: a comment naming the check is not the check.
    expect(assertsFreshness('// TODO: beforeAll(assertDistFreshIfPresent);')).toBe(false);

    expect(assertsFreshness('beforeAll(assertDistFresh);')).toBe(true);
    expect(assertsFreshness('beforeAll(assertDistFreshIfPresent);')).toBe(true);
    expect(assertsFreshness('beforeAll(() => {});')).toBe(false);
  });

  it('the helper it points at exists and exports both entry points', async () => {
    // A gate whose remedy does not resolve is a dead end (#273's lesson about
    // citations, applied to a test's own instruction).
    const helper = path.join(TESTS_ROOT, 'helpers', 'dist-freshness.ts');
    expect(statSync(helper).isFile()).toBe(true);
    const mod = await import('../helpers/dist-freshness');
    expect(typeof mod.assertDistFresh).toBe('function');
    expect(typeof mod.assertDistFreshIfPresent).toBe('function');
  });
});
