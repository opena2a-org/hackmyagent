import { describe, it, expect } from 'vitest';
import { findingTier, compareFindingsByTier } from '../../src/ui/finding-tier';

/**
 * Tier ranker for `── Findings ──` rendering order. Closes #134.
 *
 *   1  Active malice (CRED-HARVEST, EXFIL, RCE, observed PROMPT-INJECT)
 *   2  Capability / governance violations (sprawl, jailbreak, SOUL bypass/gap/missing)
 *   3  Missing-defense-in-depth (no injection resistance, no trust hierarchy)
 *   4  Hygiene (incomplete frontmatter, unverified publisher, no hash)
 *   5  Project-level (default — gitignore, project chrome)
 */

describe('findingTier — attackClass mapping (tier 1)', () => {
  it('credential harvest is tier 1 (active malice)', () => {
    expect(findingTier({ attackClass: 'CRED-HARVEST' })).toBe(1);
    expect(findingTier({ attackClass: 'CRED-EXFIL' })).toBe(1);
    expect(findingTier({ attackClass: 'CRED-EXPOSURE' })).toBe(1);
  });

  it('exfiltration / RCE / observed injection are tier 1', () => {
    expect(findingTier({ attackClass: 'DATA-EXFIL' })).toBe(1);
    expect(findingTier({ attackClass: 'SKILL-EXFIL' })).toBe(1);
    expect(findingTier({ attackClass: 'HEARTBEAT-RCE' })).toBe(1);
    expect(findingTier({ attackClass: 'CMD-INJECT' })).toBe(1);
    // PROMPT-INJECT alone (no checkId override) = observed injection
    expect(findingTier({ attackClass: 'PROMPT-INJECT' })).toBe(1);
  });
});

describe('findingTier — attackClass mapping (tier 2)', () => {
  it('capability sprawl is tier 2', () => {
    expect(findingTier({ attackClass: 'SCOPE-WILDCARD' })).toBe(2);
    expect(findingTier({ attackClass: 'CAPABILITY-CREEP' })).toBe(2);
    expect(findingTier({ attackClass: 'MCP-SCOPE-WILDCARD' })).toBe(2);
  });

  it('governance violations are tier 2 (including SOUL-GAP and SOUL-MISSING)', () => {
    expect(findingTier({ attackClass: 'SOUL-BYPASS' })).toBe(2);
    expect(findingTier({ attackClass: 'SOUL-CONTRADICTION' })).toBe(2);
    expect(findingTier({ attackClass: 'SOUL-GAP' })).toBe(2);
    expect(findingTier({ attackClass: 'SOUL-MISSING' })).toBe(2);
  });

  it('jailbreak / authority confusion are tier 2', () => {
    expect(findingTier({ attackClass: 'JAILBREAK' })).toBe(2);
    expect(findingTier({ attackClass: 'AUTHORITY-CONFUSION' })).toBe(2);
  });
});

describe('findingTier — checkId overrides (run before attackClass)', () => {
  it('AST-PROMPT-003 (Missing Injection Resistance) is tier 3 even though it emits PROMPT-INJECT', () => {
    expect(findingTier({ checkId: 'AST-PROMPT-003', attackClass: 'PROMPT-INJECT' })).toBe(3);
  });

  it('AST-PROMPT-004 (No Trust Hierarchy) is tier 3 even though it emits AUTHORITY-CONFUSION', () => {
    expect(findingTier({ checkId: 'AST-PROMPT-004', attackClass: 'AUTHORITY-CONFUSION' })).toBe(3);
  });

  it('AST-PROMPT-005 is tier 3', () => {
    expect(findingTier({ checkId: 'AST-PROMPT-005', attackClass: 'AUTHORITY-CONFUSION' })).toBe(3);
  });

  it('AST-GOV-001 (Critical Governance Domain Gap) is tier 2 (governance violation, not defense gap)', () => {
    expect(findingTier({ checkId: 'AST-GOV-001', attackClass: 'SOUL-GAP' })).toBe(2);
  });

  it('AST-GOV-003 (No Governance Constraints) is tier 2', () => {
    expect(findingTier({ checkId: 'AST-GOV-003', attackClass: 'SOUL-MISSING' })).toBe(2);
  });
});

describe('findingTier — checkId fallback (attackClass absent)', () => {
  it('credential check IDs map to tier 1', () => {
    expect(findingTier({ checkId: 'AST-CRED-001' })).toBe(1);
    expect(findingTier({ checkId: 'CRED-001' })).toBe(1);
    expect(findingTier({ checkId: 'AGENT-CRED-001' })).toBe(1);
  });

  it('SKILL-003 (Heartbeat Installation) and SKILL-022 (Env Var Exfil) are tier 1', () => {
    expect(findingTier({ checkId: 'SKILL-003' })).toBe(1);
    expect(findingTier({ checkId: 'SKILL-022' })).toBe(1);
  });

  it('AST-GOV-002 (no override entry) falls through prefix → tier 2', () => {
    expect(findingTier({ checkId: 'AST-GOV-002' })).toBe(2);
  });

  it('AST-PROMPT-001 (Jailbreak Susceptibility) without attackClass falls through prefix → tier 3', () => {
    // In real output it carries attackClass=JAILBREAK and tiers to 2 via that.
    // Without attackClass, the AST-PROMPT- prefix fallback puts it in tier 3 —
    // a conservative classification (defense gap rather than active malice).
    expect(findingTier({ checkId: 'AST-PROMPT-001' })).toBe(3);
  });

  it('hygiene checks are tier 4', () => {
    expect(findingTier({ checkId: 'SKILL-001' })).toBe(4); // Unsigned Skill
    expect(findingTier({ checkId: 'SKILL-020' })).toBe(4); // Incomplete Frontmatter
    expect(findingTier({ checkId: 'SUPPLY-001' })).toBe(4); // Unverified Publisher
    expect(findingTier({ checkId: 'SUPPLY-004' })).toBe(4); // Version Drift
  });

  it('SKILL-FRONTMATTER and ORG-SKILL-SPREAD attackClasses are tier 4 (hygiene/supply)', () => {
    expect(findingTier({ attackClass: 'SKILL-FRONTMATTER' })).toBe(4);
    expect(findingTier({ attackClass: 'ORG-SKILL-SPREAD' })).toBe(4);
  });

  it('unknown check IDs default to tier 5 (project-level)', () => {
    expect(findingTier({ checkId: 'UNKNOWN-XYZ' })).toBe(5);
    expect(findingTier({})).toBe(5);
  });
});

describe('findingTier — attackClass overrides hygiene checkId fallback', () => {
  it('attackClass=CRED-HARVEST beats checkId=SKILL-020 (hygiene checkId NOT in override list)', () => {
    expect(findingTier({ checkId: 'SKILL-020', attackClass: 'CRED-HARVEST' })).toBe(1);
  });
});

describe('compareFindingsByTier — sort order', () => {
  it('tier 1 sorts before tier 4 regardless of severity', () => {
    const malice = { attackClass: 'CRED-HARVEST', severity: 'medium' };
    const hygiene = { checkId: 'SKILL-020', severity: 'high' };
    const sorted = [hygiene, malice].sort(compareFindingsByTier);
    expect(sorted[0]).toBe(malice);
    expect(sorted[1]).toBe(hygiene);
  });

  it('within tier 4, critical sorts before high', () => {
    const a = { checkId: 'SUPPLY-001', severity: 'high' };
    const b = { checkId: 'SUPPLY-004', severity: 'critical' };
    const sorted = [a, b].sort(compareFindingsByTier);
    expect(sorted[0]).toBe(b);
    expect(sorted[1]).toBe(a);
  });

  it('benign skill (hygiene + missing-defense HIGHs) leads with missing-defense, not hygiene', () => {
    // Real findings from `secure ~/.opena2a/corpus/skill/benign/clean-skill`.
    const findings = [
      { checkId: 'SKILL-020', name: 'Incomplete Frontmatter', severity: 'high' },
      { checkId: 'SUPPLY-001', name: 'Unverified Publisher', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'SUPPLY-004', name: 'Version Drift Detection', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'AST-PROMPT-003', name: 'Missing Injection Resistance', severity: 'high', attackClass: 'PROMPT-INJECT' },
      { checkId: 'AST-PROMPT-004', name: 'No Trust Hierarchy', severity: 'high', attackClass: 'AUTHORITY-CONFUSION' },
    ];
    const sorted = [...findings].sort(compareFindingsByTier);
    // Tier-3 missing-defense findings now lead the list.
    expect(sorted[0].checkId).toBe('AST-PROMPT-003');
    expect(sorted[1].checkId).toBe('AST-PROMPT-004');
    // Tier-4 hygiene drops to the back.
    expect(sorted.slice(2).map(f => f.checkId).sort()).toEqual(
      ['SKILL-020', 'SUPPLY-001', 'SUPPLY-004'].sort(),
    );
  });

  it('buggy skill (capability + missing-defense + hygiene) leads with capability/governance, not missing-defense or hygiene', () => {
    // Real findings from `secure ~/.opena2a/corpus/skill/buggy/caps-sprawl-skill`.
    const findings = [
      { checkId: 'SKILL-020', name: 'Incomplete Frontmatter', severity: 'high' },
      { checkId: 'SUPPLY-001', name: 'Unverified Publisher', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'SUPPLY-004', name: 'Version Drift Detection', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'AST-PROMPT-003', name: 'Missing Injection Resistance', severity: 'high', attackClass: 'PROMPT-INJECT' },
      { checkId: 'AST-PROMPT-004', name: 'No Trust Hierarchy', severity: 'high', attackClass: 'AUTHORITY-CONFUSION' },
      { checkId: 'AST-PROMPT-001', name: 'Jailbreak Susceptibility', severity: 'high', attackClass: 'JAILBREAK' },
      { checkId: 'AST-GOV-001', name: 'Critical Governance Domain Gap', severity: 'medium', attackClass: 'SOUL-GAP' },
      { checkId: 'AST-GOV-003', name: 'No Governance Constraints', severity: 'medium', attackClass: 'SOUL-MISSING' },
    ];
    const sorted = [...findings].sort(compareFindingsByTier);
    // Top-3: tier 2, ordered by severity (HIGH first then MEDIUMs).
    expect(sorted[0].name).toBe('Jailbreak Susceptibility'); // HIGH tier 2
    const top3Tier2Names = sorted.slice(0, 3).map(f => f.name).sort();
    expect(top3Tier2Names).toEqual([
      'Critical Governance Domain Gap',
      'Jailbreak Susceptibility',
      'No Governance Constraints',
    ]);
  });

  it('benign top-3 ≠ buggy top-3 — the visual distinction the issue requires', () => {
    const benign = [
      { checkId: 'SKILL-020', severity: 'high' },
      { checkId: 'SUPPLY-001', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'SUPPLY-004', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'AST-PROMPT-003', severity: 'high', attackClass: 'PROMPT-INJECT' },
      { checkId: 'AST-PROMPT-004', severity: 'high', attackClass: 'AUTHORITY-CONFUSION' },
    ].sort(compareFindingsByTier).slice(0, 3).map(f => f.checkId);

    const buggy = [
      { checkId: 'SKILL-020', severity: 'high' },
      { checkId: 'SUPPLY-001', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'SUPPLY-004', severity: 'high', attackClass: 'ORG-SKILL-SPREAD' },
      { checkId: 'AST-PROMPT-003', severity: 'high', attackClass: 'PROMPT-INJECT' },
      { checkId: 'AST-PROMPT-004', severity: 'high', attackClass: 'AUTHORITY-CONFUSION' },
      { checkId: 'AST-PROMPT-001', severity: 'high', attackClass: 'JAILBREAK' },
      { checkId: 'AST-GOV-001', severity: 'medium', attackClass: 'SOUL-GAP' },
      { checkId: 'AST-GOV-003', severity: 'medium', attackClass: 'SOUL-MISSING' },
    ].sort(compareFindingsByTier).slice(0, 3).map(f => f.checkId);

    // Pre-fix, both lists led with [SKILL-020, SUPPLY-001, SUPPLY-004].
    // Post-fix, benign leads with AST-PROMPT-{003,004} (missing-defense),
    // buggy leads with [AST-PROMPT-001, AST-GOV-001, AST-GOV-003] (governance).
    expect(benign).not.toEqual(buggy);
    expect(buggy).toContain('AST-PROMPT-001'); // Jailbreak surfaces top
    expect(buggy).toContain('AST-GOV-001'); // Critical Gov Gap surfaces top
  });

  it('malicious skill (CRED-HARVEST critical) still leads — tier 1 beats tier 2', () => {
    const findings = [
      { checkId: 'AST-GOV-001', severity: 'high', attackClass: 'SOUL-GAP' },
      { checkId: 'AST-CRED-001', severity: 'critical', attackClass: 'CRED-HARVEST' },
      { checkId: 'SKILL-022', severity: 'critical' },
      { checkId: 'SUPPLY-001', severity: 'high' },
    ];
    const sorted = [...findings].sort(compareFindingsByTier);
    expect(sorted[0].checkId).toBe('AST-CRED-001');
    expect(sorted[1].checkId).toBe('SKILL-022');
    expect(sorted[2].checkId).toBe('AST-GOV-001');
    expect(sorted[3].checkId).toBe('SUPPLY-001');
  });
});
