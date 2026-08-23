// The verdict line says when the analyst dissents.
//
// The defect: a credential-exfiltrating shell script scores a clean 100, because
// the deterministic checks key on credentials PRESENT in a file, not on a
// command that STEALS them. The analyst can route such a file to `attack` at
// high severity, but that escalation is advisory and non-scoring by [CDS-024]
// (~22% measured FP rate on dual-use security code), so it rendered only in a
// footer below a verdict line saying the tree was fine. Measured 2026-08-23 on
// 8c767f6, one `.sh` holding a single exfiltrating curl beside a complete
// `.gitignore`:
//
//   Security  100/100
//   Verdict   No security issues detected. This library looks safe to use.
//
// An earlier draft cited 98/100 for this. That number was the same fixture
// WITHOUT a `.gitignore` — 98 was an unrelated `Missing .gitignore` finding,
// not the exfiltration. The blind spot is a clean 100.
//
// What is below is the PURE half only: the rule for which escalations count and
// what the clause says. That half is easy to get right. The hard half — WHERE
// the clause is appended — is deliberately not tested here; see the block after
// `analystDissentSuffix` for why, and for the seam that would close it.
//
// Do not re-add a source-grep guard for the ordering. Three were written and
// three were defeated, each leaving this suite green while the clause was
// erased at runtime.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  analystDissentSuffix,
  dissentingFiles,
  type DissentingEscalation,
} from '../../src/ui/analyst-dissent';

const attack = (file: string): DissentingEscalation => ({ file, routed: 'attack' });
const abstain = (file: string): DissentingEscalation => ({ file, routed: 'abstain' });

describe('dissentingFiles', () => {
  it('returns the files the analyst routed to attack', () => {
    expect(dissentingFiles([attack('.mcp.json')])).toEqual(['.mcp.json']);
  });

  it('excludes abstains — the abstention gate absorbs model hedges, and they must not reach the verdict line', () => {
    expect(dissentingFiles([abstain('a.md'), abstain('b.md')])).toEqual([]);
  });

  it('counts only the attack half of a mixed set', () => {
    expect(dissentingFiles([abstain('a.md'), attack('b.json'), abstain('c.md')])).toEqual(['b.json']);
  });

  it('counts a file once when a producer emits two escalations for it', () => {
    expect(dissentingFiles([attack('.mcp.json'), attack('.mcp.json')])).toEqual(['.mcp.json']);
  });

  it('is empty for undefined and for an empty array', () => {
    expect(dissentingFiles(undefined)).toEqual([]);
    expect(dissentingFiles([])).toEqual([]);
  });
});

describe('analystDissentSuffix', () => {
  it('names the dissent and points at the section that renders it', () => {
    expect(analystDissentSuffix([attack('.mcp.json')])).toBe(
      ' (analyst dissents on 1 file — see NanoMind Coverage Escalations)',
    );
  });

  it('pluralises on more than one file', () => {
    expect(analystDissentSuffix([attack('a.json'), attack('b.json')])).toBe(
      ' (analyst dissents on 2 files — see NanoMind Coverage Escalations)',
    );
  });

  it('carries a count and a section name, never a path', () => {
    // Escalation `file` values come out of the scanned tree and are
    // attacker-influenced. The footer escapes them with `escapePathForDisplay`
    // before printing a row; putting a second, differently-escaped copy on the
    // most-read line in the output is the thing this clause avoids.
    const hostile = 'evil\u001b[2J/\nVerdict   No security issues detected./.mcp.json';
    const suffix = analystDissentSuffix([attack(hostile)]);
    expect(suffix).not.toContain('.mcp.json');
    expect(suffix).not.toContain('\u001b');
    expect(suffix).not.toContain('\n');
    expect(suffix).toBe(' (analyst dissents on 1 file — see NanoMind Coverage Escalations)');
  });

  it('is empty with no escalations, so the caller can append unconditionally', () => {
    expect(analystDissentSuffix(undefined)).toBe('');
    expect(analystDissentSuffix([])).toBe('');
    expect(analystDissentSuffix([abstain('a.md')])).toBe('');
  });
});

// ── What is NOT guarded here, and why ────────────────────────────────────
//
// The clause must be appended as the LAST mutation of `verdictDisplay.value`:
// two disclosure branches ASSIGN that value outright, both gated on
// `totalFindings === 0`, which is exactly the scan where a dissent is the only
// adverse signal. Composed any earlier it is silently deleted in the one case
// it exists for.
//
// THERE IS NO TEST FOR THAT HERE, deliberately. Three successive versions of a
// source-grep guard were each defeated by a spelling its author had not
// thought of — an alias, bracket access with a template key,
// `Object.defineProperty`, and finally `const sink = verdictDisplay!;`, which
// is the `!` idiom this very file already uses. Each defeat left the suite
// green while the clause was erased at runtime, and each fix added a new
// coverage claim that was itself false.
//
// A guard that cannot be distinguished from its absence is not a guard, and
// one that advertises class coverage it does not have is worse than none: it
// buys a reader confidence that is not there. So it is deleted rather than
// extended a fourth time.
//
// The real test is behavioural and is now known to be cheap: the render can be
// driven end-to-end with no analyst daemon and no model by swapping the
// orchestrator export in `require.cache` and spawning the built CLI. That is
// tracked in #560 and is the only
// thing that closes this class. Until it lands, the invariant is held by the
// comment at the append site in `cli.ts`, and by nothing else. Say so.

describe('a malformed escalation does not crash the render EARLIER than before', () => {
  // Scope note, because the obvious stronger claim is false: this does NOT make
  // a malformed escalation survivable. The footer at `cli.ts` still does
  // `allEscalations.filter(...)` and still dereferences `esc.file`, so a `null`
  // element still kills the run — as it did before this change. What the guard
  // buys is that the crash lands no earlier than it used to: without it, the
  // throw moves up and takes the Categories and Verdict lines with it.
  const bad = (v: unknown) => analystDissentSuffix(v as never);

  it('returns empty rather than throwing on a null element', () => {
    expect(() => bad([null])).not.toThrow();
    expect(bad([null])).toBe('');
  });

  it('returns empty rather than throwing on a non-array with a length', () => {
    expect(() => bad({ length: 2 })).not.toThrow();
    expect(bad({ length: 2 })).toBe('');
  });

  it('ignores an element with no routed field', () => {
    expect(bad([{ file: 'a.md' }])).toBe('');
  });
});

describe('the clause comes off the green', () => {
  const cli = readFileSync(join(__dirname, '../../src/cli.ts'), 'utf8');

  it('downgrades a good tone to warning, and only from good', () => {
    // Both sibling disclosure branches drop green with an explicit comment
    // saying why. This one discloses a named attack class at HIGH/CRITICAL and
    // must not be the exception. One-way: a critical/warning verdict keeps its
    // tone, so the advisory channel can withdraw an all-clear but never soften
    // a fail-direction verdict. Verified by pty capture: 32m -> 33m.
    expect(cli).toContain("if (dissentSuffix !== '' && verdictDisplay.tone === 'good')");
    expect(cli).toContain("verdictDisplay.tone = 'warning'");
  });
});

describe('the footer headline and the clause count the same way', () => {
  const cli = readFileSync(join(__dirname, '../../src/cli.ts'), 'utf8');

  it('derives the attack-route footer count from dissentingFiles', () => {
    // Two attack escalations on one path printed "dissents on 1 file" beside
    // "flagged 2 files" — two numbers for one scan, from two derivations.
    // NOTE the abstain headline two lines below it still counts entries; that
    // is pre-existing and untouched here.
    expect(cli).toContain('const flaggedCount = dissentingFiles(allEscalations).length;');
  });
});
