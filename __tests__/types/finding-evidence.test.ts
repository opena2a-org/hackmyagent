import { describe, it, expect } from 'vitest';
import {
  type Evidence,
  type ConceptId,
  isPositiveEvidence,
  isAbsenceEvidence,
  isMixedEvidence,
  isValidEvidence,
  isConceptId,
} from '../../src/types/finding-evidence';

describe('Evidence discriminated union', () => {
  it('narrows to PositiveEvidence on kind="positive"', () => {
    const e: Evidence = {
      kind: 'positive',
      lines: [{ n: 3, content: 'evil line', why: 'because' }],
    };
    if (isPositiveEvidence(e)) {
      expect(e.lines[0].n).toBe(3);
      expect(e.lines[0].content).toBe('evil line');
    } else {
      throw new Error('expected PositiveEvidence narrowing');
    }
  });

  it('narrows to AbsenceEvidence on kind="absence"', () => {
    const e: Evidence = {
      kind: 'absence',
      observed: {
        lines: [{ n: 1, content: 'shell:*' }],
        summary: 'grants shell wildcard',
      },
      expected: [{ constraint: 'override-resistance', rationale: 'must reject runtime injection' }],
    };
    if (isAbsenceEvidence(e)) {
      expect(e.expected[0].constraint).toBe('override-resistance');
    } else {
      throw new Error('expected AbsenceEvidence narrowing');
    }
  });

  it('narrows to MixedEvidence on kind="mixed"', () => {
    const e: Evidence = {
      kind: 'mixed',
      positive: { lines: [{ n: 3, content: 'exfil', why: 'sends to webhook.site' }] },
      absence: {
        observed: { lines: [{ n: 1, content: 'shell:*' }], summary: 'wildcard shell' },
        expected: [{ constraint: 'trust-hierarchy', rationale: 'no source ranking' }],
      },
    };
    if (isMixedEvidence(e)) {
      expect(e.positive.lines).toHaveLength(1);
      expect(e.absence.expected).toHaveLength(1);
    } else {
      throw new Error('expected MixedEvidence narrowing');
    }
  });
});

describe('isValidEvidence runtime guard', () => {
  it('accepts positive', () => {
    expect(isValidEvidence({ kind: 'positive', lines: [] })).toBe(true);
  });

  it('accepts absence', () => {
    expect(isValidEvidence({ kind: 'absence', observed: { lines: [], summary: '' }, expected: [] })).toBe(true);
  });

  it('accepts mixed', () => {
    expect(isValidEvidence({ kind: 'mixed', positive: { lines: [] }, absence: { observed: { lines: [], summary: '' }, expected: [] } })).toBe(true);
  });

  it('rejects unknown kind', () => {
    expect(isValidEvidence({ kind: 'magic', whatever: true })).toBe(false);
  });

  it('rejects null and primitives', () => {
    expect(isValidEvidence(null)).toBe(false);
    expect(isValidEvidence(undefined)).toBe(false);
    expect(isValidEvidence('positive')).toBe(false);
    expect(isValidEvidence(42)).toBe(false);
  });
});

describe('isConceptId runtime guard', () => {
  it('accepts every ConceptId in the union', () => {
    const concepts: ConceptId[] = [
      'soul-governance',
      'secretless-vault',
      'mcp-tool-isolation',
      'injection-resistance',
      'trust-hierarchy',
      'signing-and-pinning',
    ];
    for (const c of concepts) {
      expect(isConceptId(c)).toBe(true);
    }
  });

  it('rejects unknown strings', () => {
    expect(isConceptId('made-up-concept')).toBe(false);
    expect(isConceptId('')).toBe(false);
    expect(isConceptId(null)).toBe(false);
    expect(isConceptId(123)).toBe(false);
  });
});
