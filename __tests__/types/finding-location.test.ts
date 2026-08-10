/**
 * `resolveFindingLine` — the recovery path, and the refusal at the end of it.
 *
 * WHY THIS FILE EXISTS. The module shipped with no direct test. Measured on the
 * suite as it stood, two mutations left all 262 test files green:
 *
 *   1. deleting the ENTIRE recovery path (return `finding.line` or undefined,
 *      never consult evidence or content) — 117/117 green in the file's own
 *      area and green across the suite;
 *   2. changing the final `return undefined` to `return 1` — green, while
 *      fabricating a line on 11 findings across two real trees. The module's own
 *      docblock calls that branch "the load-bearing one".
 *
 * Both are now pinned here, in the two directions they fail in. A recovery that
 * does not recover and a refusal that does not refuse are different defects and
 * neither can be caught by testing only the other.
 *
 * Assertions are derived from the fixtures — `content.split('\n')` — never
 * copied from the function's output, so an implementation that changes what it
 * returns cannot satisfy them by having its answer written down here.
 */

import { describe, it, expect } from 'vitest';
import type { Evidence } from '../../src/types/finding-evidence';
import {
  MIN_VERBATIM_TRIGGER_LENGTH,
  firstLineFromEvidence,
  resolveFindingLine,
  verbatimTriggers,
} from '../../src/types/finding-location';

/** A trigger long enough to clear the specificity floor, and unique in CONTENT. */
const TRIGGER = "exec(userSuppliedCommand)";

const CONTENT = [
  '# agent runner',                      // 1
  'import os',                           // 2
  '',                                    // 3
  'def run(userSuppliedCommand):',       // 4
  `    return ${TRIGGER}`,               // 5
  '',                                    // 6
  'run("ls")',                           // 7
  '',
].join('\n');

/** Derived from the fixture, never read back out of the function under test. */
const TRIGGER_LINE = CONTENT.split('\n').findIndex(l => l.includes(TRIGGER)) + 1;

describe('resolveFindingLine: an existing line is returned unchanged', () => {
  it('keeps a line the detector already recorded', () => {
    expect(resolveFindingLine({ file: 'a.py', line: 4 }, CONTENT)).toBe(4);
  });

  it('ignores a non-1-based line and falls through to recovery', () => {
    // 0 is not a citation. Falling through is what lets a detector that emits a
    // sentinel still produce a usable finding.
    expect(resolveFindingLine({ file: 'a.py', line: 0, evidence: TRIGGER }, CONTENT))
      .toBe(TRIGGER_LINE);
  });
});

describe('resolveFindingLine: the RECOVERY path', () => {
  // MUTATION (a): delete the recovery path — every assertion in this block must
  // fail. They are the only assertions in the suite that exercise it.

  it('recovers the line a structured evidence record already cited', () => {
    const evidence: Evidence = {
      kind: 'positive',
      lines: [{ n: TRIGGER_LINE, content: TRIGGER, why: 'command injection' }],
    };
    expect(resolveFindingLine({ file: 'a.py', evidence }, undefined)).toBe(TRIGGER_LINE);
    // …and without needing the content at all, which is the point of this step:
    // the detector already answered, so no search is run.
    expect(firstLineFromEvidence(evidence)).toBe(TRIGGER_LINE);
  });

  it('recovers the line of an absence record"s observed block', () => {
    const evidence: Evidence = {
      kind: 'absence',
      observed: { lines: [{ n: TRIGGER_LINE, content: TRIGGER }], summary: 'ungoverned exec' },
      expected: [{ constraint: 'input-validation', rationale: 'untrusted argv' }],
    };
    expect(resolveFindingLine({ file: 'a.py', evidence }, undefined)).toBe(TRIGGER_LINE);
  });

  it('recovers from an absence record"s observed line CONTENT when n is unusable', () => {
    // MUTATION: `verbatimTriggers`' absence branch -> `[]`. This is the only
    // assertion that fails. Every other absence fixture in this file carries a
    // usable `n`, so `firstLineFromEvidence` answers before the trigger search
    // runs and the branch could be deleted with both suites green — the branch
    // was reachable code with no reachable test.
    //
    // `n: 0` is the shape a detector emits when it has the text but not the
    // offset: not a usable 1-based line, so the search is the only route left.
    const evidence: Evidence = {
      kind: 'absence',
      observed: { lines: [{ n: 0, content: TRIGGER }], summary: 'ungoverned exec' },
      expected: [{ constraint: 'input-validation', rationale: 'untrusted argv' }],
    };
    expect(verbatimTriggers(evidence)).toEqual([TRIGGER]);
    expect(resolveFindingLine({ file: 'a.py', evidence }, CONTENT)).toBe(TRIGGER_LINE);
  });

  it('recovers from the ABSENCE half of a mixed record, not only the positive half', () => {
    // Same branch class, second spelling. `verbatimTriggers`' mixed case
    // concatenates two line arrays and the existing mixed fixture only fills
    // the positive one, so dropping the absence half of that concatenation was
    // also unobserved.
    const evidence = {
      kind: 'mixed',
      positive: { lines: [] },
      absence: {
        observed: { lines: [{ n: 0, content: TRIGGER }], summary: 'no governance' },
        expected: [{ constraint: 'c', rationale: 'r' }],
      },
    } as unknown as Evidence;
    expect(verbatimTriggers(evidence)).toEqual([TRIGGER]);
    expect(resolveFindingLine({ file: 'a.py', evidence }, CONTENT)).toBe(TRIGGER_LINE);
  });

  it('recovers a line by locating the VERBATIM trigger in the artifact', () => {
    const line = resolveFindingLine({ file: 'a.py', evidence: TRIGGER }, CONTENT);
    expect(line).toBe(TRIGGER_LINE);
    // The structural claim, not just the number: the line it names is a line
    // that actually holds the trigger. A constant would satisfy the number on
    // this fixture and fail here on any other.
    expect(CONTENT.split('\n')[line! - 1]).toContain(TRIGGER);
  });

  it('recovers from a structured evidence record"s line CONTENT when n is absent', () => {
    // The mixed shape with no usable `n`: the trigger text is still verbatim, so
    // the search is the recovery.
    const evidence = {
      kind: 'mixed',
      positive: { lines: [{ n: 0, content: TRIGGER, why: 'exec' }] },
      absence: {
        observed: { lines: [], summary: 'no governance' },
        expected: [{ constraint: 'c', rationale: 'r' }],
      },
    } as unknown as Evidence;
    expect(verbatimTriggers(evidence)).toContain(TRIGGER);
    expect(resolveFindingLine({ file: 'a.py', evidence }, CONTENT)).toBe(TRIGGER_LINE);
  });

  it('recovers the FIRST line of a multi-line artifact, not a default', () => {
    // A trigger that genuinely sits on line 1, so "returns 1" and "recovered 1"
    // are indistinguishable HERE — which is exactly why the refusal block below
    // exists and why this case alone is not enough.
    const first = resolveFindingLine({ file: 'a.py', evidence: '# agent runner' }, CONTENT);
    expect(first).toBe(1);
  });
});

describe('resolveFindingLine: the REFUSAL', () => {
  // MUTATION (b): `return undefined` -> `return 1` — every assertion in this
  // block must fail. A confidently wrong citation is worse than an absent one,
  // and `1` is confidently wrong on every finding whose trigger is not on the
  // first line.

  it('refuses when the finding has no file', () => {
    expect(resolveFindingLine({ line: undefined, evidence: TRIGGER }, CONTENT)).toBeUndefined();
  });

  it('refuses when no artifact content was supplied', () => {
    expect(resolveFindingLine({ file: 'a.py', evidence: TRIGGER }, undefined)).toBeUndefined();
  });

  it('refuses when the evidence is a dedupe ROLLUP that is not in the artifact', () => {
    // The real shape: `[5 instances across: a.ts, b.ts]`. A rolled-up finding has
    // no single location, and inventing one points the reader at line 1 of a file
    // the rollup may not even be about.
    const rollup = '[5 instances across: src/a.ts, src/b.ts]';
    expect(CONTENT).not.toContain(rollup);
    expect(resolveFindingLine({ file: 'a.py', evidence: rollup }, CONTENT)).toBeUndefined();
  });

  it('refuses when the evidence is a SYNTHESIZED label, not artifact text', () => {
    const label = 'GitHub personal access token';
    expect(CONTENT).not.toContain(label);
    expect(resolveFindingLine({ file: 'a.py', evidence: label }, CONTENT)).toBeUndefined();
  });

  it('refuses when the finding carries no evidence at all', () => {
    expect(resolveFindingLine({ file: 'a.py' }, CONTENT)).toBeUndefined();
  });

  it('refuses on an empty artifact rather than naming its first line', () => {
    expect(resolveFindingLine({ file: 'a.py', evidence: TRIGGER }, '')).toBeUndefined();
  });

  it('refuses for an absence record whose observed block is summary-only', () => {
    const evidence: Evidence = {
      kind: 'absence',
      observed: { lines: [], summary: 'no Bash restriction anywhere in the file' },
      expected: [{ constraint: 'bash-allowlist', rationale: 'unrestricted' }],
    };
    expect(resolveFindingLine({ file: 'SOUL.md', evidence }, CONTENT)).toBeUndefined();
  });
});

/* ================================================================== *
 * The three rules that decide whether a trigger has EARNED a citation.
 *
 * EVERY NEEDLE BELOW IS A LITERAL. The pins these replace built both the
 * accepted and the rejected needle out of `MIN_VERBATIM_TRIGGER_LENGTH`
 * (`'import o'.slice(0, MIN - 1)` and `line.slice(0, MIN)`), so the fixture
 * moved with the constant and setting the floor to 1 left the block green — it
 * asserted "the floor is wherever the floor is", which is not a pin. A literal
 * needle of a stated length cannot move with the implementation.
 * ================================================================== */

/**
 * Fixture for the three rules. Line 4 and line 8 are byte-identical on purpose:
 * that duplication is what makes a long, specific-looking trigger AMBIGUOUS.
 */
const PIN_CONTENT = [
  'const a = 1;', //                        1
  'let handler = null;', //                 2
  'function connect() {', //                3
  '  handler = openSocket();', //           4
  '}', //                                   5
  'const credential = readEnv();', //       6
  'function reconnect() {', //              7
  '  handler = openSocket();', //           8  (identical to line 4)
  '}', //                                   9
  'export default reconnect;', //          10
  '',
].join('\n');

/** Occurrences of `needle` in `PIN_CONTENT`, counted from the fixture. */
function occurrences(needle: string): number {
  return PIN_CONTENT.split(needle).length - 1;
}

/** 1-based line holding `needle`, derived from the fixture. */
function lineOf(needle: string): number {
  return PIN_CONTENT.split('\n').findIndex(l => l.includes(needle)) + 1;
}

describe('a trigger earns a citation only when it is SPECIFIC enough', () => {
  // MUTATION: set `MIN_VERBATIM_TRIGGER_LENGTH` to 1 — the first assertion must
  // fail. It is the only place in the suite where a present, unique, non-generic
  // needle is rejected for its length alone.

  const SEVEN = 'const a';
  const EIGHT = 'export d';

  it('the fixture supports the claim: both needles are present and unique', () => {
    // Non-vacuity. If either needle stopped being unique, the uniqueness rule
    // would decide these cases and the floor would be untested.
    expect(SEVEN.length).toBe(7);
    expect(EIGHT.length).toBe(8);
    expect(occurrences(SEVEN)).toBe(1);
    expect(occurrences(EIGHT)).toBe(1);
    expect(lineOf(SEVEN)).toBe(1);
    expect(lineOf(EIGHT)).toBe(10);
  });

  it('refuses a 7-character trigger that IS present and unique', () => {
    expect(resolveFindingLine({ file: 'a.ts', evidence: SEVEN }, PIN_CONTENT)).toBeUndefined();
  });

  it('accepts an 8-character trigger — the floor is a floor, not a wall', () => {
    expect(resolveFindingLine({ file: 'a.ts', evidence: EIGHT }, PIN_CONTENT))
      .toBe(lineOf(EIGHT));
  });

  it('the shipped floor is the one these literals were written against', () => {
    // Stated once, so raising or lowering the constant is a deliberate edit that
    // shows up here rather than a silent change to what the two tests above mean.
    expect(MIN_VERBATIM_TRIGGER_LENGTH).toBe(8);
  });
});

describe('a trigger earns a citation only when it identifies ONE place', () => {
  // MUTATION: delete the `occursExactlyOnce` guard — the first assertion must
  // fail, returning line 4 for a trigger that is equally on line 8.

  const AMBIGUOUS = 'handler = openSocket();';
  const UNIQUE = 'export default reconnect;';

  it('the fixture supports the claim: one needle twice, one needle once', () => {
    // Non-vacuity, and the whole point of the fixture: the ambiguous needle is
    // long, specific-looking, and clears the floor with room to spare. Length is
    // not what disqualifies it.
    expect(occurrences(AMBIGUOUS)).toBe(2);
    expect(occurrences(UNIQUE)).toBe(1);
    expect(AMBIGUOUS.length).toBeGreaterThan(MIN_VERBATIM_TRIGGER_LENGTH);
  });

  it('refuses a trigger that occurs twice, rather than naming the first', () => {
    const line = resolveFindingLine({ file: 'a.ts', evidence: AMBIGUOUS }, PIN_CONTENT);
    expect(line).toBeUndefined();
    // Named explicitly: 4 is what a leftmost `indexOf` returns, and "a line where
    // this text appears" is not the claim a citation makes.
    expect(line).not.toBe(4);
  });

  it('accepts the same shape of trigger when it occurs exactly once', () => {
    expect(resolveFindingLine({ file: 'a.ts', evidence: UNIQUE }, PIN_CONTENT))
      .toBe(lineOf(UNIQUE));
  });
});

describe('a dictionary word is a category, not a location', () => {
  // MUTATION: delete the `GENERIC_TRIGGER_VOCABULARY` guard — the first
  // assertion must fail, returning line 6 for the bare word `credential`.
  //
  // This is the shape `mapRiskSurfaces` emits as CRED-HARVEST evidence:
  // `/password|credential|api[_-]?key|secret|token/i.exec(content)?.[0]`.
  // `credential` is 10 characters and `password` is 8, so the length floor lets
  // both through, and the first occurrence of either is a comment or a policy
  // sentence far more often than it is the flagged value.

  it('the fixture supports the claim: the bare word is present, unique, and long enough', () => {
    // Non-vacuity in all three directions the other two rules could take over.
    expect(occurrences('credential')).toBe(1);
    expect('credential'.length).toBeGreaterThanOrEqual(MIN_VERBATIM_TRIGGER_LENGTH);
    expect(lineOf('credential')).toBe(6);
  });

  it('refuses the bare vocabulary word even though it is present and unique', () => {
    const line = resolveFindingLine({ file: 'a.ts', evidence: 'credential' }, PIN_CONTENT);
    expect(line).toBeUndefined();
    expect(line).not.toBe(6);
  });

  /**
   * The `i` flag on `GENERIC_TRIGGER_VOCABULARY` needs its own fixture.
   *
   * This case used to run `'Credential'` against `PIN_CONTENT`, which holds
   * only the lowercase spelling — so `occursExactlyOnce` returned false and
   * REFUSED THE TRIGGER BEFORE the vocabulary regex was ever consulted. The
   * companion assertion used lowercase `'password'`, which the regex matches
   * with or without the flag. Neither half could observe the thing the test is
   * named for: dropping `/i` left the whole suite green while
   * `resolveFindingLine` started citing the first occurrence of a bare
   * capitalized keyword — the manufactured citation this module exists to stop.
   *
   * CASE_CONTENT therefore carries the CAPITALIZED words, uniquely, so
   * `occursExactlyOnce` succeeds and the vocabulary guard is the only rule left
   * that can refuse. Only vocabulary words of at least
   * `MIN_VERBATIM_TRIGGER_LENGTH` characters can be tested this way — a shorter
   * one (`secret`, `token`, `api_key`) is refused by the length floor first,
   * which would make the case vacuous again for a different reason.
   */
  const CASE_CONTENT = [
    'const a = 1;', //                       1
    'let Credential = readEnv();', //        2
    'const Password = process.env.PW;', //   3
    'export default a;', //                  4
    '',
  ].join('\n');

  it.each(['Credential', 'Password'])(
    'the fixture supports the claim: %s is present, unique, and long enough',
    (word) => {
      // Each guard that could answer ahead of the vocabulary rule, ruled out.
      expect(CASE_CONTENT.split(word).length - 1).toBe(1);
      expect(word.length).toBeGreaterThanOrEqual(MIN_VERBATIM_TRIGGER_LENGTH);
      // And the branch really is reachable: the same fixture DOES yield a line
      // for a longer excerpt that merely contains the word. Without this, a
      // future change that made the whole fixture unresolvable would leave the
      // refusals below passing for the wrong reason.
      const excerpt = CASE_CONTENT.split('\n').find((l) => l.includes(word))!;
      expect(resolveFindingLine({ file: 'a.ts', evidence: excerpt }, CASE_CONTENT))
        .toBe(CASE_CONTENT.split('\n').findIndex((l) => l.includes(word)) + 1);
    },
  );

  it.each(['Credential', 'Password'])(
    'refuses the bare vocabulary word case-insensitively: %s',
    (word) => {
      // Drop the `i` flag and this returns the word's line instead.
      expect(resolveFindingLine({ file: 'a.ts', evidence: word }, CASE_CONTENT))
        .toBeUndefined();
    },
  );

  it('accepts a real excerpt that merely CONTAINS the word', () => {
    // The rule rejects the bare word, not the concept: a verbatim line of the
    // artifact is still a location.
    const excerpt = 'const credential = readEnv();';
    expect(occurrences(excerpt)).toBe(1);
    expect(resolveFindingLine({ file: 'a.ts', evidence: excerpt }, PIN_CONTENT))
      .toBe(lineOf(excerpt));
  });
});
