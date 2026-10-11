// #977 — the severity table in docs/SECURITY_CHECKS.md must predict the score.
//
// The table listed flat deductions (Critical -15, High -10, Medium -5, Low -2)
// while `calculateSecurityScore` adds severity weights 25/15/8/3 to a sum and
// scores round(100 * exp(-sum / 150)), with governance findings at 0.4 and
// findings past the third per check at 0.1. A reader adding up the table got
// 33 for 1 critical, 3 high, 4 medium and 1 low; the scanner gives 50.
//
// This reads the documented weights, formula, adjustments, cap and worked
// examples, and checks each against the scoring code, so the doc cannot drift
// from the formula again without this failing.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { calculateSecurityScore } from '../../src/hardening';
import { VERDICT_FAIL_CLAMP, clampScoreToVerdictBand } from '../../src/ui/verdict-band';

const DOC = readFileSync(join(__dirname, '..', '..', 'docs', 'SECURITY_CHECKS.md'), 'utf-8');
const SECTION = DOC.slice(DOC.indexOf('## Severity Levels'), DOC.indexOf('\n---', DOC.indexOf('## Severity Levels')));

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
type Sev = (typeof SEVERITIES)[number];
const ORDINALS: Record<string, number> = { first: 1, second: 2, third: 3, fourth: 4, fifth: 5 };

function documentedWeights(): Partial<Record<Sev, number>> {
  const weights: Partial<Record<Sev, number>> = {};
  for (const sev of SEVERITIES) {
    const label = sev[0].toUpperCase() + sev.slice(1);
    const m = SECTION.match(new RegExp(`^\\| \\*\\*${label}\\*\\* \\| ([\\d.]+) \\|`, 'm'));
    if (m) weights[sev] = Number(m[1]);
  }
  return weights;
}

function match(re: RegExp): string {
  const m = SECTION.match(re);
  expect(m, `docs/SECURITY_CHECKS.md Severity Levels section should match ${re}`).not.toBeNull();
  return m![1];
}

interface Example { label: string; sum: number; raw: number; shown: number }

function documentedExamples(): Example[] {
  const start = SECTION.indexOf('| Open findings |');
  if (start < 0) return [];
  return SECTION.slice(start).split('\n').slice(2)
    .filter(line => line.startsWith('| '))
    .map(line => {
      const [label, sum, score] = line.split('|').slice(1, 4).map(c => c.trim());
      const raw = Number(score.match(/^(\d+)/)![1]);
      const shown = score.match(/shown as (\d+)/);
      return { label, sum: Number(sum), raw, shown: shown ? Number(shown[1]) : raw };
    });
}

function findingsFor(label: string) {
  const parts = label.split(', ');
  const governance = parts.includes('governance');
  const oneCheck = parts.includes('one check');
  const findings: Array<{ passed: boolean; severity: Sev; checkId: string; category: string }> = [];
  for (const part of parts) {
    const m = part.match(/^(\d+) (critical|high|medium|low)$/);
    if (!m) continue;
    for (let i = 0; i < Number(m[1]); i++) {
      findings.push({
        passed: false,
        severity: m[2] as Sev,
        checkId: oneCheck ? 'DOC-ONE-001' : `DOC-${m[2]}-${i}`,
        category: governance ? 'governance' : 'credentials',
      });
    }
  }
  return findings;
}

describe('docs/SECURITY_CHECKS.md score table matches the scoring code (#977)', () => {
  const weights = documentedWeights();
  const formula = SECTION.match(/score = round\(100 \* exp\(-sum \/ (\d+)\)\)/);
  const decay = formula ? Number(formula[1]) : NaN;

  it('documents a weight for every severity and the formula they feed', () => {
    expect(Object.keys(weights).sort()).toEqual([...SEVERITIES].sort());
    expect(formula, 'score formula line').not.toBeNull();
  });

  it.each(SEVERITIES)('one %s finding scores what the documented weight and formula predict', sev => {
    const { score } = calculateSecurityScore([{ passed: false, severity: sev, checkId: 'DOC-001', category: 'credentials' }]);
    expect(score).toBe(Math.round(100 * Math.exp(-(weights[sev] ?? NaN) / decay)));
  });

  it('documents the cap the verdict band applies', () => {
    expect(Number(match(/the score shown is capped at (\d+)/))).toBe(VERDICT_FAIL_CLAMP);
  });

  it('every worked example matches the documented rules and the scoring code', () => {
    const governanceWeight = Number(match(/Governance findings count at ([\d.]+) of their weight/));
    const overflow = match(/After the (\w+) finding from one check, each further finding counts at ([\d.]+)/);
    const perCheck = ORDINALS[overflow];
    const overflowWeight = Number(match(/each further finding counts at ([\d.]+) of its weight/));
    const examples = documentedExamples();

    // The examples must exercise both adjustments and the cap, or a drift in
    // any of them would pass unnoticed.
    expect(examples.some(e => e.label.includes('governance'))).toBe(true);
    expect(examples.some(e => e.label.includes('one check') && findingsFor(e.label).length > perCheck)).toBe(true);
    expect(examples.some(e => e.shown !== e.raw)).toBe(true);

    for (const example of examples) {
      const findings = findingsFor(example.label);
      expect(findings.length, example.label).toBeGreaterThan(0);

      const perCheckCount = new Map<string, number>();
      let documentedSum = 0;
      for (const f of findings) {
        const n = (perCheckCount.get(f.checkId) ?? 0) + 1;
        perCheckCount.set(f.checkId, n);
        documentedSum += (weights[f.severity] ?? NaN)
          * (f.category === 'governance' ? governanceWeight : 1)
          * (n <= perCheck ? 1 : overflowWeight);
      }
      expect(example.sum, `${example.label}: Sum column`).toBeCloseTo(documentedSum, 9);
      expect(Math.round(100 * Math.exp(-example.sum / decay)), `${example.label}: formula`).toBe(example.raw);

      const { score: raw } = calculateSecurityScore(findings);
      expect(raw, `${example.label}: scanner score`).toBe(example.raw);
      expect(clampScoreToVerdictBand(raw, findings).score, `${example.label}: score shown`).toBe(example.shown);
    }
  });
});
