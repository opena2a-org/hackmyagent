import { describe, it, expect } from 'vitest';
import { findingTier } from '../../src/ui/finding-tier';
import { getTaxonomyMap } from '../../src/hardening/taxonomy';

/**
 * Coverage contract — every `attackClass` string emitted by HMA must tier ≤ 4
 * (i.e., not silently fall to tier 5 "project chrome").
 *
 * Drives the fix for the Phase 4.5 adversarial-review C-1 (SANDBOX-ESCAPE
 * silently tier-5) and C-2 (TME lowercase classes silently tier-5) findings
 * during the issue-#134 rerank.
 *
 * Two surfaces walked:
 *   - getTaxonomyMap()           — every checkId → attackClass mapping in
 *                                  src/hardening/taxonomy.ts (deterministic
 *                                  scanner + nemoclaw + soul findings).
 *   - TME_CLASSES (literal)      — the TME classifier's `CLASSES` constant
 *                                  (src/nanomind-core/inference/tme-classifier.ts).
 *                                  Mirrored here so the test can fail without
 *                                  loading the model runtime.
 *
 * If a future analyzer introduces a new `attackClass` literal, either the
 * taxonomy mirrors it and this test fails (FAILS LOUDLY — fix before merge)
 * or the analyzer doesn't go through the taxonomy and a separate regression
 * is needed.
 *
 * Mirror constant: keep this list in sync with
 * src/nanomind-core/inference/tme-classifier.ts:CLASSES.
 */
const TME_CLASSES = [
  'exfiltration',
  'injection',
  'privilege_escalation',
  'persistence',
  'credential_abuse',
  'lateral_movement',
  'social_engineering',
  'policy_violation',
  'benign',
  'steganography',
];

describe('findingTier coverage — every emitted attackClass tiers ≤ 4', () => {
  it('every taxonomy attackClass tiers ≤ 4 (no silent tier-5 misses)', () => {
    const taxonomy = getTaxonomyMap();
    const distinctAttackClasses = new Set(Object.values(taxonomy));
    const failures: Array<{ ac: string; tier: number }> = [];
    for (const ac of distinctAttackClasses) {
      const tier = findingTier({ attackClass: ac });
      if (tier === 5) {
        failures.push({ ac, tier });
      }
    }
    expect(
      failures,
      `${failures.length} taxonomy attackClass(es) silently land in tier 5: ${failures.map(f => f.ac).join(', ')}. Add them to the appropriate TIER_*_ATTACK_CLASSES set in src/ui/finding-tier.ts.`,
    ).toEqual([]);
  });

  it('every TME (NanoMind) classifier class tiers ≤ 4', () => {
    const failures: Array<{ ac: string; tier: number }> = [];
    for (const ac of TME_CLASSES) {
      if (ac === 'benign') continue; // 'benign' never reaches the renderer
      const tier = findingTier({ attackClass: ac });
      if (tier === 5) {
        failures.push({ ac, tier });
      }
    }
    expect(
      failures,
      `${failures.length} TME class(es) silently land in tier 5: ${failures.map(f => f.ac).join(', ')}. Either canonicalAttackClass should map them, or TIER_*_ATTACK_CLASSES needs the canonical (UPPERCASE-DASH) form.`,
    ).toEqual([]);
  });

  it('canonicalization: snake_case TME labels match dash-uppercase tier sets', () => {
    // privilege_escalation → PRIVILEGE-ESCALATION (in TIER_1)
    expect(findingTier({ attackClass: 'privilege_escalation' })).toBe(1);
    expect(findingTier({ attackClass: 'PRIVILEGE_ESCALATION' })).toBe(1);
    expect(findingTier({ attackClass: 'PRIVILEGE-ESCALATION' })).toBe(1);
    // credential_abuse → CREDENTIAL-ABUSE
    expect(findingTier({ attackClass: 'credential_abuse' })).toBe(1);
    // social_engineering → SOCIAL-ENGINEERING
    expect(findingTier({ attackClass: 'social_engineering' })).toBe(1);
    // policy_violation → POLICY-VIOLATION (governance)
    expect(findingTier({ attackClass: 'policy_violation' })).toBe(2);
  });

  it('SANDBOX-ESCAPE (HMA-NMC-031 docker --privileged) tiers 1', () => {
    // Concrete regression for the Phase 4.5 C-1 finding.
    expect(findingTier({ attackClass: 'SANDBOX-ESCAPE' })).toBe(1);
    expect(findingTier({ attackClass: 'NEMO-SANDBOX-ESCAPE' })).toBe(1);
  });

  it('NEMO-CRED-LEAK + RAG-POISON + GATEWAY-EXPLOIT tier 1', () => {
    expect(findingTier({ attackClass: 'NEMO-CRED-LEAK' })).toBe(1);
    expect(findingTier({ attackClass: 'RAG-POISON' })).toBe(1);
    expect(findingTier({ attackClass: 'GATEWAY-EXPLOIT' })).toBe(1);
    expect(findingTier({ attackClass: 'MCP-EXPLOIT' })).toBe(1);
  });

  it('SOUL-* governance / impersonation attacks tier appropriately', () => {
    // Active identity / impersonation attacks → tier 1
    expect(findingTier({ attackClass: 'SOUL-IMPERSONATE' })).toBe(1);
    expect(findingTier({ attackClass: 'SOUL-HIJACK' })).toBe(1);
    expect(findingTier({ attackClass: 'SOUL-INJECT' })).toBe(1);
    expect(findingTier({ attackClass: 'SOUL-POISON' })).toBe(1);
    expect(findingTier({ attackClass: 'PHANTOM-SOUL' })).toBe(1);
    // Governance violations / drift → tier 2
    expect(findingTier({ attackClass: 'SOUL-DRIFT' })).toBe(2);
    expect(findingTier({ attackClass: 'SOUL-FORK' })).toBe(2);
    expect(findingTier({ attackClass: 'SOUL-BOUNDARY' })).toBe(2);
    expect(findingTier({ attackClass: 'SOUL-DELEGATE' })).toBe(2);
  });
});
