/**
 * HMA-28 — the confinement harnesses parse JSON from stdout only.
 *
 * The pass-21 pre-push failure was measured to a harness defect, not a product
 * one: `run()` in three spawn suites returned stdout and stderr concatenated
 * into one string, and `json()` / the SARIF cell JSON.parsed that merged
 * stream. Any stderr byte a spawned process emits after the JSON body —
 * load-induced on a saturated machine — is trailing garbage to `JSON.parse`,
 * which throws, nulls the body, and failed 34 of 42 tests in
 * obstruction-disclosure alone (54 across the three files, reproduced
 * byte-for-byte by injecting a single stderr line via
 * `__tests__/helpers/stderr-injection.cjs`).
 *
 * The fix keeps BOTH streams in `run()`'s return: `stdout` for every JSON and
 * SARIF parse, the merged `out` for the text assertions that legitimately want
 * whichever channel the message lands on. This suite pins that split:
 *
 *   AC1 — in the three harnesses, every JSON.parse reads the stdout stream and
 *         the merged stream is still built (removing it would push the text
 *         assertions back onto one channel by accident, the inverse defect);
 *   AC2 — the mechanism, executed: a child spawned with the injection module
 *         on NODE_OPTIONS emits the extra stderr line, the merged-stream parse
 *         throws on it, the stdout-only parse does not;
 *   AC3 — the shape cannot come back silently anywhere under `__tests__`: a
 *         helper that concatenates stdout and stderr into one string must not
 *         feed that string to JSON.parse.
 *
 * The full-suite form of AC2 (the three harnesses run under
 * `NODE_OPTIONS="--require __tests__/helpers/stderr-injection.cjs"`, red at
 * base d6fade15, green at the fix) is recorded with the task; see the
 * injection module's header for the exact command.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const TESTS = path.resolve(__dirname, '..');
const INJECTOR = path.join(TESTS, 'helpers', 'stderr-injection.cjs');

/** The three harnesses the pass-21 measurement bound, and their parse sites. */
const HARNESSES: Record<string, number> = {
  'repo/obstruction-disclosure.test.ts': 2, // json() and the SARIF cell
  'cli/secure-unread-input-gate.test.ts': 1, // json()
  'cli/secure-unread-directory-gate.test.ts': 1, // json()
};

/** The pinned stdout-only parse shape the fix installs at all four sites. */
const STDOUT_PARSE = /JSON\.parse\(res\.stdout\.slice\(res\.stdout\.indexOf\('\{'\)\)\)/g;

/**
 * A string built from both streams of one spawn result, in the two spellings
 * the defect used: a returned property (`out: `) and a local binding. Matching
 * the template-literal shape of the three base helpers is deliberate — see
 * AC3's docline; a genuinely new concatenation spelling should be caught in
 * review by this file's header, not silently blessed by an over-broad regex.
 */
const MERGED_STREAM_FIELD = [
  /(\w+)\s*:\s*`[^`]*\$\{\s*res\.stdout[^`]*\$\{\s*res\.stderr[^`]*`/g,
  /(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{\s*res\.stdout[^`]*\$\{\s*res\.stderr[^`]*`/g,
];

function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (/\.(?:ts|cts|mts|js|cjs|mjs)$/.test(e.name)) out.push(full);
  }
  return out;
}

describe('HMA-28 — stdout-only JSON parsing in the confinement harnesses', () => {
  it('HMA-28.AC1 every JSON and SARIF parse in the three harnesses reads res.stdout, and the merged out survives for text assertions', () => {
    for (const [rel, parseCount] of Object.entries(HARNESSES)) {
      const text = fs.readFileSync(path.join(TESTS, rel), 'utf-8');
      // run() must expose both streams under the names the split assigns them.
      expect(text, `${rel}: run() no longer returns the stdout-only stream`).toContain(
        "stdout: res.stdout ?? ''",
      );
      expect(text, `${rel}: run() no longer returns the merged stream the text assertions read`).toContain(
        "out: `${res.stdout ?? ''}${res.stderr ?? ''}`",
      );
      // Every parse site reads stdout alone — no site parses the merged stream,
      // and no site drifted to a shape this pin does not see. (A regex, not a
      // string literal: the criterion greps `__tests__` for the defect's exact
      // spelling and must find only benchmark-composite's stdout-only `out`.)
      expect(text, `${rel}: a parse site reads the merged stream again`).not.toMatch(/JSON\.parse\(res\.out/);
      expect(
        (text.match(STDOUT_PARSE) ?? []).length,
        `${rel}: expected ${parseCount} stdout-only parse site(s)`,
      ).toBe(parseCount);
      expect(
        (text.match(/JSON\.parse\(/g) ?? []).length,
        `${rel}: a JSON.parse outside the pinned stdout-only shape appeared`,
      ).toBe(parseCount);
    }
  });

  it('HMA-28.AC2 an injected stderr line breaks the merged-stream parse and leaves the stdout-only parse intact', () => {
    const res = spawnSync(
      process.execPath,
      ['-e', "process.stdout.write(JSON.stringify({ ok: true }))"],
      {
        encoding: 'utf-8',
        timeout: 30_000,
        env: { ...process.env, NODE_OPTIONS: `--require "${INJECTOR}"` },
      },
    );
    expect(res.status).toBe(0);
    // Precondition proven, not assumed: the module injected its line.
    expect(res.stderr).toContain('hma-28 injected stderr line');

    // The pre-fix shape: one stderr byte after the JSON is trailing garbage.
    const merged = `${res.stdout ?? ''}${res.stderr ?? ''}`;
    expect(() => JSON.parse(merged.slice(merged.indexOf('{')))).toThrow();

    // The fixed shape: the same stderr byte is invisible to the parse.
    const stdout = res.stdout ?? '';
    expect(JSON.parse(stdout.slice(stdout.indexOf('{'))).ok).toBe(true);
  });

  it('HMA-28.AC3 no helper under __tests__ concatenates stdout and stderr into a string that is then JSON.parsed', () => {
    const offenders: string[] = [];
    for (const file of walk(TESTS)) {
      if (path.resolve(file) === path.resolve(__filename)) continue;
      const text = fs.readFileSync(file, 'utf-8');
      for (const detector of MERGED_STREAM_FIELD) {
        for (const m of text.matchAll(detector)) {
          const field = m[1];
          // A merged stream is fine for text assertions; parsing it is the defect.
          const parsed = new RegExp(`JSON\\.parse\\(\\s*(?:res\\.)?${field}[.[)]`);
          if (parsed.test(text)) {
            offenders.push(`${path.relative(TESTS, file)} parses merged stream '${field}'`);
          }
        }
      }
    }
    expect(
      offenders,
      'a run() helper concatenates stdout and stderr and JSON.parses the result — ' +
        'parse res.stdout alone (see this file\'s header)',
    ).toEqual([]);
  });
});
