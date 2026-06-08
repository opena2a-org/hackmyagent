import { describe, it, expect } from 'vitest';
import { renderGovernanceModel, buildDomainSummaries } from './governance-model';
import { GOVERNANCE_CATALOG_SIZE } from './scanner';

describe('renderGovernanceModel', () => {
  const output = renderGovernanceModel();

  it('reports the full catalog total (9 domains, 72 controls)', () => {
    const summaries = buildDomainSummaries();
    expect(summaries).toHaveLength(9);
    expect(GOVERNANCE_CATALOG_SIZE).toBe(72);
    expect(output).toContain('scan-soul governance model: 9 domains, 72 controls');
  });

  it('numbers domains 11-19 per the OASB-2 spec, with context for the gap at 1-10 (P3)', () => {
    const domainLines = output.split('\n').filter((l) => l.startsWith('Domain '));
    expect(domainLines).toHaveLength(9);
    // OASB-2 numbers the behavioral domains 11-19 (extending OASB-1's 1-10).
    // This is the canonical spec numbering, not a leaked internal index — see
    // CHANGELOG 0.23.7. The renderer must keep these ids, not renumber to 1-9.
    domainLines.forEach((line, i) => {
      expect(line.startsWith(`Domain ${11 + i} — `)).toBe(true);
    });
    // And it must explain the 11-19 numbering so the 1-10 gap doesn't read as
    // missing domains.
    expect(output).toContain('OASB-2 behavioral domains');
  });
});
