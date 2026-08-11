// Regression gate for the `scan-soul --deep` self-referential pointer and
// the silent deep pass (closes the two cheap halves of #260).
//
// `scan-soul <hardened-soul>` correctly discloses that coverage is
// keyword-detected and points at the escape hatch:
//
//   Keyword conformance scan — controls implemented as prose may not be
//   detected. Semantic pass: hackmyagent scan-soul <dir> --deep
//
// Running `--deep` re-printed that same line — the escape hatch suggesting
// itself while already running, a dead end for anyone who followed it — and
// printed nothing at all for ~55s while it made one LLM round-trip per
// undetected control, reading as a hang.
//
// The third item in #260 — the semantic tier recovering too few prose
// controls — is a matcher-quality problem tracked separately.
//
// The copy decision is a pure function so it can be gated without a live LLM
// backend; the progress counter's wiring is asserted against cli.ts because
// its whole contract is which stream it writes to and when.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { soulScopeDisclosureLines } from '../../src/ui/soul-scope-disclosure';

const BASE = {
  missing: 20,
  upgraded: 3,
  prefix: 'hackmyagent',
  directory: '/tmp/agent',
};

/** The `--deep` pointer, exactly as the non-deep disclosure emits it. */
const DEEP_POINTER = /Semantic pass: hackmyagent scan-soul \/tmp\/agent --deep/;

describe('scan-soul scope disclosure (#251 + #260)', () => {
  it('points at --deep on a keyword-only run', () => {
    // Non-vacuity for every "must not point at --deep" assertion below: the
    // pointer has to exist somewhere, or they pass for the wrong reason.
    const lines = soulScopeDisclosureLines({ ...BASE, deep: false, deepAvailable: true });
    expect(lines.join('\n')).toMatch(DEEP_POINTER);
  });

  it('never points at --deep on a --deep run', () => {
    const lines = soulScopeDisclosureLines({ ...BASE, deep: true, deepAvailable: true });
    expect(lines.join('\n')).not.toMatch(DEEP_POINTER);
    expect(lines.join('\n')).not.toMatch(/--deep/);
  });

  it('reports what the semantic pass recovered', () => {
    const lines = soulScopeDisclosureLines({ ...BASE, deep: true, deepAvailable: true });
    const text = lines.join('\n');
    expect(text).toContain('3 controls recovered');
    expect(text).toContain('remaining 20');
  });

  it('singularizes a single recovered control', () => {
    const text = soulScopeDisclosureLines({
      ...BASE, deep: true, deepAvailable: true, upgraded: 1,
    }).join('\n');
    expect(text).toContain('1 control recovered');
    expect(text).not.toContain('1 controls');
  });

  it('states plainly when the semantic pass recovered nothing', () => {
    // The originally reported case. It must not read as a success, and it
    // must not send the user back to --deep.
    const text = soulScopeDisclosureLines({
      ...BASE, deep: true, deepAvailable: true, upgraded: 0, missing: 23,
    }).join('\n');
    expect(text).toContain('0 controls recovered');
    expect(text).toContain('remaining 23');
    expect(text).not.toMatch(/--deep/);
  });

  it('hands over a next step that has not already been spent', () => {
    // No dead ends: --deep is used up by the time this renders, so the
    // disclosure has to offer something else that still helps.
    const text = soulScopeDisclosureLines({ ...BASE, deep: true, deepAvailable: true }).join('\n');
    expect(text).toContain('hackmyagent harden-soul /tmp/agent');
  });

  it('keeps the pointer when --deep was requested but no backend was reachable', () => {
    // The pass never ran, so it has not been spent — but the copy must not
    // claim it did.
    const text = soulScopeDisclosureLines({ ...BASE, deep: true, deepAvailable: false }).join('\n');
    expect(text).toMatch(/could not run/);
    expect(text).not.toContain('recovered by the semantic pass');
  });

  it('leaves the keyword-only copy byte-identical to the #251 contract', () => {
    const lines = soulScopeDisclosureLines({ ...BASE, deep: false, deepAvailable: true });
    expect(lines).toEqual([
      'Keyword conformance scan — controls implemented as prose may not be detected. ' +
        'Semantic pass: hackmyagent scan-soul /tmp/agent --deep',
    ]);
  });
});

describe('scan-soul --deep progress counter (#260)', () => {
  const CLI_SOURCE = readFileSync(join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');

  it('hands every input of the gate to the predicate that decides it', () => {
    // #285 — this used to grep the inline five-term boolean and assert each
    // term appeared in it. The comment justifying that read: "a behavioral
    // test would need a live backend and a PTY." That is no longer true. The
    // gate is `shouldShowDeepProgress` in `src/ui/progress-gate.ts`, and its
    // behaviour — including deny-dominance over every combination — is
    // asserted for real in `__tests__/ui/fix-summary-and-progress-gate.test.ts`
    // with no backend and no PTY.
    //
    // What is left for the source to prove is the WIRING: that `cli.ts`
    // actually asks, and asks with all five inputs. A perfect predicate wired
    // to four of them is the #260 shape — a good unit layer whose only
    // consumer is unguarded.
    const start = CLI_SOURCE.indexOf('const showDeepProgress');
    expect(start, 'showDeepProgress gate not found — did it move?').toBeGreaterThan(-1);
    const callSite = CLI_SOURCE.slice(start, start + 320);

    // #454 — the CI input is `isCiMode(options)`, not a bare `options.ci`.
    // The strip in main() removes --ci from argv before parse(), so `options.ci`
    // is always undefined and wiring it here passed the gate a permanently dead
    // value. This still asserts all five inputs are wired; it pins the CI one to
    // the form that actually carries the signal. A bare `options.ci` here is the
    // defect, so accepting it would make this guard assert the bug.
    expect(callSite, 'the gate must delegate to the tested predicate').toContain('shouldShowDeepProgress');
    for (const input of ['options.deep', 'options.json', 'isCiMode(options)', 'globalCiMode', 'process.stderr.isTTY']) {
      expect(callSite, `${input} must be passed to the gate`).toContain(input);
    }
  });

  it('writes the counter to stderr, never stdout', () => {
    const start = CLI_SOURCE.indexOf('Semantic pass: ${analyzed}/${total}');
    expect(start, 'progress counter not found').toBeGreaterThan(-1);
    expect(CLI_SOURCE.slice(Math.max(0, start - 120), start)).toContain('process.stderr.write');
  });

  it('clears the counter so it does not linger above the report', () => {
    const start = CLI_SOURCE.indexOf('const showDeepProgress');
    const region = CLI_SOURCE.slice(start, start + 1400);
    expect(region).toMatch(/\\r\$\{' '\.repeat\(\d+\)\}\\r/);
  });
});
