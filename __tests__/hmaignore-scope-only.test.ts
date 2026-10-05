/**
 * #457 — our own `.hmaignore` may state scope, never waive a check.
 *
 * Seven `!CHECK-*` family wildcards sat in this repo's tracked `.hmaignore` from
 * 2026-04-03. They were added as a workaround for #131's pathless noise floor and
 * they outlived it, with three consequences:
 *
 *   1. They held `secure . --ci` at `100/100 · No security issues found · exit 0`
 *      on published 0.27.0, so our own CI never exercised the laundering path
 *      #450 exists to close. The tool's own gate was green because it had been
 *      told not to look.
 *   2. A family wildcard erases the record of the checks that PASS as well as the
 *      ones that fail. Of the 29 check IDs the seven lines covered, 14 —
 *      including all four AUTH checks, LOG-002 and TOOL-003 — appeared nowhere in
 *      `--json` at all: not in `findings`, not in `allFindings`, not in
 *      `suppressed`, not in `outOfScope`. We could not have proved a negative
 *      about any of them.
 *   3. `!SEC-*` pre-waives a `SEC-005` nobody has written yet.
 *
 * This is a guard, not a preference. The failure mode it exists for is a red gate
 * at the end of a long day and a one-line "temporary" `!CHECK-NNN`, which is
 * exactly how the original seven were added and how they survived four years of
 * review. A finding we believe is inapplicable gets a disposition in the issue
 * tracker; a scope statement gets a path rule, which `secure` discloses on its
 * `Scope` line.
 *
 * Scoped to THIS repo's file. It says nothing about whether `!CHECK-*` should
 * remain a supported feature for users — that is a CLI contract question and is
 * open (see #457).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { parseHmaIgnore } from '../src/hardening/scanner';

const REPO_ROOT = path.resolve(__dirname, '..');
const HMAIGNORE = path.join(REPO_ROOT, '.hmaignore');

describe("#457 — this repo's .hmaignore states scope, never waives a check", () => {
  // Guards the assertion below. If the file is ever renamed or dropped, a
  // `[].every(...)` over a missing file passes vacuously and this whole test
  // becomes decoration while the rule it protects quietly lapses.
  it('the file exists and carries the path rules this test is about', () => {
    expect(existsSync(HMAIGNORE)).toBe(true);
    const rules = readFileSync(HMAIGNORE, 'utf-8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'));
    expect(rules).toContain('test-fixtures/');
    expect(rules.length).toBeGreaterThan(5);
  });

  it('contains no check-ID or check-family suppression rule', () => {
    const offenders = readFileSync(HMAIGNORE, 'utf-8')
      .split('\n')
      .map((l, i) => ({ line: i + 1, text: l.trim() }))
      .filter((l) => l.text.startsWith('!'));

    // Named, not counted: a bare `toEqual([])` on a failure prints the whole
    // file and leaves the reader to find the offending line themselves.
    expect(
      offenders.map((o) => `${path.basename(HMAIGNORE)}:${o.line} ${o.text}`),
    ).toEqual([]);
  });
});

/**
 * The scanner we ship scans its own shipped source.
 *
 * Until this guard, the same file carried whole-directory rules on
 * `src/hardening/`, `src/nanomind-core/` and `src/attack/payloads/`, plus seven
 * more shipped-path rules that matched nothing at all. A whole-path rule on
 * shipped source is invisible in practice: the `Scope` line names the
 * directory, never what it hid, and a rule that once covered one finding keeps
 * covering every finding that later lands under it. Two of the findings it hid
 * were literal zero-width characters in files that ship in `dist/`.
 *
 * The test trees stay out by a whole-path rule. Anything else is declared as
 * `<file>:<CHECK-ID> # <reason>`: one file, one exact check, a reason a reader
 * can check against that file.
 */
describe("this repo's .hmaignore excludes no shipped path", () => {
  const TEST_TREES = new Set(['test-fixtures/', 'test/', '__tests__/']);
  const today = new Date().toISOString().slice(0, 10);
  const parsed = parseHmaIgnore(readFileSync(HMAIGNORE, 'utf-8'), today);

  it('every line parses', () => {
    expect(parsed.errors.map((e) => `.hmaignore:${e.line} ${e.rule} (${e.error})`)).toEqual([]);
  });

  it('the only whole-path rules are the three test trees', () => {
    const wholePath = parsed.rules.filter((r) => r.channel === 'hmaignore-path');
    expect(wholePath.map((r) => r.path).sort()).toEqual([...TEST_TREES].sort());
  });

  it('every narrowed rule names one existing file, one exact check and a reason', () => {
    const narrowed = parsed.rules.filter((r) => r.channel === 'hmaignore-path-check');
    expect(narrowed.length).toBeGreaterThan(0);
    const offenders = narrowed
      .filter((r) => {
        const target = path.join(REPO_ROOT, r.path ?? '');
        const isFile = existsSync(target) && statSync(target).isFile();
        const exactCheck = /^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$/.test(r.checkId ?? '');
        return !isFile || !exactCheck || !(r.reason && r.reason.trim().length > 20);
      })
      .map((r) => `.hmaignore:${r.line} ${r.rule}`);
    expect(offenders).toEqual([]);
  });
});

describe('shipped source carries no literal zero-width codepoint', () => {
  // U+200B..U+200D, word joiner and BOM: the set UNICODE-STEGO-001 reads as
  // hidden text. Source that needs one spells it as an escape, which compiles
  // to the same string and leaves nothing invisible in `dist/`.
  const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/;

  function sourceFiles(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) return sourceFiles(full);
      return /\.(ts|js|mjs|cjs|json)$/.test(entry.name) ? [full] : [];
    });
  }

  it('no file under src/ contains one', () => {
    const files = sourceFiles(path.join(REPO_ROOT, 'src'));
    expect(files.length).toBeGreaterThan(100);
    const offenders = files.flatMap((file) =>
      readFileSync(file, 'utf-8')
        .split('\n')
        .flatMap((text, i) => (ZERO_WIDTH.test(text) ? [`${path.relative(REPO_ROOT, file)}:${i + 1}`] : [])),
    );
    expect(offenders).toEqual([]);
  });
});
