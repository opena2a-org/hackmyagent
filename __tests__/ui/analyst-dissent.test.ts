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
  composeVerdictLine,
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

// ── The order, held by a function a test can call (#560) ──────────────────
//
// The clause must land AFTER the two disclosure verdicts: both ASSIGN the
// line outright and both are gated on `totalFindings === 0`, which is exactly
// the scan where a dissent is the only adverse signal. Composed any earlier it
// is silently deleted in the one case it exists for.
//
// Three source-grep guards for this order were each defeated by a spelling
// their author had not thought of (an alias, bracket access, defineProperty,
// `const sink = verdictDisplay!;`), so the order now lives in one pure
// function and is asserted by calling it. No source-grep test for the same
// property is kept beside these: two guards for one property is how the
// weaker one stops being maintained.
describe('composeVerdictLine', () => {
  const clean = { value: 'No security issues detected.', tone: 'good' as const };
  const clause = ' (analyst dissents on 1 file — see NanoMind Coverage Escalations)';
  const gap = 'No issues in what was examined — but 7 stopped at a file cap. '
    + 'This is not a clean bill of health for the whole target.';
  const quick = 'Quick scan found nothing in what it checked.';

  it('keeps the clause when the coverage-gap disclosure replaces the line', () => {
    const out = composeVerdictLine({ base: clean, coverageGapVerdict: gap, escalations: [attack('SKILL.md')] });
    expect(out.value).toBe(gap + clause);
    expect(out.tone).toBe('warning');
  });

  it('keeps the clause when the quick-scan disclosure replaces the line', () => {
    const out = composeVerdictLine({ base: clean, quickScanVerdict: quick, escalations: [attack('SKILL.md')] });
    expect(out.value).toBe(quick + clause);
    expect(out.tone).toBe('warning');
  });

  it('lets the coverage-gap disclosure win over the quick-scan one, as it ran second', () => {
    const out = composeVerdictLine({
      base: clean, quickScanVerdict: quick, coverageGapVerdict: gap, escalations: [attack('SKILL.md')],
    });
    expect(out.value).toBe(gap + clause);
  });

  it('downgrades a good tone to warning when the clause is added, and only from good', () => {
    // One-way: the advisory channel can withdraw an all-clear but never soften
    // a fail-direction verdict.
    expect(composeVerdictLine({ base: clean, escalations: [attack('a')] }).tone).toBe('warning');
    expect(composeVerdictLine({ base: { value: 'x', tone: 'critical' }, escalations: [attack('a')] }).tone)
      .toBe('critical');
    expect(composeVerdictLine({ base: { value: 'x', tone: 'default' }, escalations: [attack('a')] }).tone)
      .toBe('default');
  });

  it('leaves the line byte-identical, tone included, with no dissent and no disclosure', () => {
    expect(composeVerdictLine({ base: clean, escalations: undefined })).toEqual(clean);
    expect(composeVerdictLine({ base: clean, escalations: [abstain('a')] })).toEqual(clean);
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
