/**
 * #285 M31 — a fix that landed must still be reported.
 *
 * Five sites in `cli.ts` build the display list with
 *
 *   (!f.passed || f.fixed) && f.file && scanner.findingAppliesTo(f, projectType)
 *
 * The `|| f.fixed` half is what keeps a repaired finding in the list after
 * the check flips `passed` to true. Reverting all five to `!f.passed` left
 * the full suite green, and the observable effect on a real `secure --fix`
 * run is not subtle — the whole report disappears:
 *
 *   - Fixed 1 issue (1 verified):
 *   -   [GIT-001] .gitignore - Missing .gitignore
 *   - 1 remaining issue has fix guidance...
 *   - Backup created: .../.hackmyagent-backup/...
 *   - Something wrong? Run `hackmyagent rollback ...` to undo all changes.
 *
 * A user who ran `--fix` would be told nothing about what changed on their
 * disk, and would not be told how to undo it. The scan still wrote files.
 *
 * This spawns the built CLI, so it asserts build freshness first: the
 * original mutation pass ran roughly half its new coverage against a stale
 * `dist/`, where a mutation in `src/` cannot turn anything red.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

let dir: string;
let output: string;

beforeAll(() => {
  assertDistFresh();

  dir = mkdtempSync(path.join(tmpdir(), 'hma-285-m31-'));
  writeFileSync(path.join(dir, 'package.json'), '{"name":"a","version":"1.0.0"}\n');

  try {
    output = execFileSync(process.execPath, [BUILT_CLI, 'secure', dir, '--fix'], {
      encoding: 'utf8',
      timeout: 240_000,
      env: { ...process.env, NO_COLOR: '1' },
    });
  } catch (e: unknown) {
    output = String((e as { stdout?: string }).stdout ?? '');
  }
}, 300_000);

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe('#285 M31 — a repaired finding stays in the report', () => {
  it('actually applied a fix, or the rest of this file proves nothing', () => {
    expect(output.length, 'no output captured — the scan did not run').toBeGreaterThan(0);
    expect(
      existsSync(path.join(dir, '.gitignore')),
      'the fixture produced no landing fix; M31 is untested',
    ).toBe(true);
  });

  it('names what it repaired', () => {
    expect(
      output,
      'a --fix run rewrote the tree and reported nothing about what it changed',
    ).toMatch(/Fixed \d+ issue/);
    expect(
      output,
      'the repaired check is not named, so the user cannot tell what was touched',
    ).toContain('GIT-001');
  });

  it('tells the user how to undo it', () => {
    // The rollback line disappears with the same mutation. A tool that
    // edits files without saying how to reverse it is a dead end.
    expect(output, 'no rollback path offered after a --fix that wrote files').toMatch(/rollback/);
  });
});
