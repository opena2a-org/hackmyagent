// A declared npm script must be runnable (#276).
//
// `package.json` declared `"lint": "eslint src --ext .ts"` and `eslint` was in
// neither dependency list, so `npm run lint` exited 127 with
// `sh: eslint: command not found`. The 127 was then swallowed by the pre-push
// hook, which runs
//
//     if grep -q '"lint"' package.json; then npm run lint 2>&1 || true; fi
//
// under a section printing "─── Running lint (warnings only) ───". So every
// quality gate that listed lint had been reporting a stage that never ran, and
// no CI workflow called it at all. (The issue says the npm wrapper exits 0;
// measured, npm propagates 127 correctly — the swallow is the `|| true`.)
//
// The class, not the symptom: any script whose leading binary is absent fails
// the same way and is just as invisible, because the thing that would notice is
// the gate that is not running.
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');
const pkg = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};

/** Shell builtins and npm itself, which need no binary on disk. */
const SHELL_PROVIDED = new Set(['npm', 'npx', 'node', 'rm', 'cd', 'echo', 'true', 'false']);

/** The first executable a script invokes. */
function leadingBinary(script: string): string {
  return script.trim().split(/\s+/)[0];
}

describe('every declared npm script can actually run (#276)', () => {
  it('declares scripts at all', () => {
    // Non-vacuity: an empty script map would satisfy every assertion below.
    expect(Object.keys(pkg.scripts).length).toBeGreaterThan(3);
  });

  it.each(Object.entries(pkg.scripts))('%s: its binary is installed', (_name, script) => {
    const bin = leadingBinary(script);
    if (SHELL_PROVIDED.has(bin)) return;
    const local = path.join(REPO_ROOT, 'node_modules', '.bin', bin);
    expect(
      existsSync(local),
      `\`${bin}\` is not in node_modules/.bin, so this script exits 127. Add it to `
      + 'devDependencies, or stop declaring a check that cannot run — a gate '
      + 'listing it reports a stage that never happened.',
    ).toBe(true);
  });

  // The specific gate the pre-push hook looks for. It greps for `"lint"` in
  // package.json and runs it, so if it is declared it has to work.
  it('lint is declared and exits 0', () => {
    expect(pkg.scripts.lint, 'the pre-push hook greps for a "lint" script').toBeDefined();
    const run = spawnSync('npm', ['run', 'lint'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 300_000,
    });
    expect(
      run.status,
      `npm run lint exited ${run.status}\n${run.stdout ?? ''}\n${run.stderr ?? ''}`,
    ).toBe(0);
  }, 300_000);

  // `lint` is a type check, which is a real static analysis and passes today —
  // deliberately NOT eslint. Adding eslint plus a TypeScript parser would bring
  // roughly a hundred transitive dev packages into a security tool's tree, and
  // this repo pins exact versions across the CLI consolidation specifically to
  // limit that. Guarded so the script cannot quietly become a no-op like `true`.
  it('lint runs a real check rather than a placeholder', () => {
    const resolved = pkg.scripts.lint.includes('npm run ')
      ? pkg.scripts[pkg.scripts.lint.replace('npm run ', '').trim()]
      : pkg.scripts.lint;
    expect(resolved, 'the lint script must resolve to a real command').toBeDefined();
    expect(resolved).toMatch(/tsc|eslint/);
    expect(resolved).not.toMatch(/^\s*(true|exit 0|echo)\b/);
  });

  it('the type check actually reads the source tree', () => {
    // A `tsconfig` that included nothing would pass in 0s and prove nothing.
    const tsconfig = path.join(REPO_ROOT, 'tsconfig.json');
    expect(existsSync(tsconfig)).toBe(true);
    expect(readdirSync(path.join(REPO_ROOT, 'src')).length).toBeGreaterThan(5);
  });
});
