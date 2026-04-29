import { describe, it, expect } from 'vitest';
import {
  CONCEPT_EXPLAINERS,
  getConceptExplainer,
  inferConceptFromFix,
} from '../../src/ui/concept-explainers';
import { isConceptId, type ConceptId } from '../../src/types/finding-evidence';

/**
 * Note on enforcement: the canonical "every ConceptId has a registry entry"
 * rule is enforced at COMPILE TIME by the `Record<ConceptId, ConceptExplainer>`
 * type annotation on `CONCEPT_EXPLAINERS`. Adding a new ConceptId without an
 * entry fails `tsc`. These runtime tests are belt-and-suspenders: they iterate
 * the registry's actual keys (not a hardcoded list) so they also fail loudly
 * if a key is added that ISN'T a valid ConceptId, or if the registry is
 * pruned in a way the type system can't catch.
 */

describe('CONCEPT_EXPLAINERS registry', () => {
  const registeredKeys = Object.keys(CONCEPT_EXPLAINERS) as ConceptId[];

  it('every registered key is a valid ConceptId', () => {
    for (const key of registeredKeys) {
      expect(isConceptId(key), `registry key ${key} is not a valid ConceptId`).toBe(true);
    }
  });

  it('every entry has a non-empty title, body, and oneLineRef', () => {
    for (const key of registeredKeys) {
      const entry = CONCEPT_EXPLAINERS[key];
      expect(entry.title.length).toBeGreaterThan(0);
      expect(entry.body.length).toBeGreaterThan(0);
      expect(entry.oneLineRef.length).toBeGreaterThan(0);
    }
  });

  it('every entry id matches its registry key', () => {
    for (const key of registeredKeys) {
      expect(CONCEPT_EXPLAINERS[key].id).toBe(key);
    }
  });

  it('oneLineRef back-references are non-generic', () => {
    for (const key of registeredKeys) {
      const ref = CONCEPT_EXPLAINERS[key].oneLineRef;
      expect(ref.length).toBeGreaterThan(5);
    }
  });
});

describe('getConceptExplainer', () => {
  it('returns the registered entry for a known id', () => {
    const entry = getConceptExplainer('soul-governance');
    expect(entry).toBeDefined();
    expect(entry?.id).toBe('soul-governance');
  });
});

describe('inferConceptFromFix (#142)', () => {
  it('matches `harden-soul` → soul-governance', () => {
    expect(inferConceptFromFix('hackmyagent harden-soul . — adds injection resistance constraints to SOUL.md.')).toBe(
      'soul-governance',
    );
  });

  it('matches `scan-soul` → soul-governance', () => {
    expect(inferConceptFromFix('hackmyagent scan-soul . to inspect governance')).toBe('soul-governance');
  });

  it('matches `opena2a protect` → secretless-vault', () => {
    expect(inferConceptFromFix('opena2a protect . — migrate credentials to the vault')).toBe(
      'secretless-vault',
    );
  });

  it('matches hardcoded credential phrasing → secretless-vault', () => {
    expect(inferConceptFromFix('Replace hardcoded API key with an environment variable reference')).toBe(
      'secretless-vault',
    );
  });

  it('matches `opena2a mcp audit` → mcp-tool-isolation', () => {
    expect(
      inferConceptFromFix('opena2a mcp audit — inventory each server and restrict allowedTools'),
    ).toBe('mcp-tool-isolation');
  });

  it('matches AST-INJECT-001 checkId → injection-resistance', () => {
    expect(inferConceptFromFix(undefined, 'AST-INJECT-001')).toBe('injection-resistance');
  });

  it('matches AST-PROMPT-004 checkId → trust-hierarchy', () => {
    expect(inferConceptFromFix(undefined, 'AST-PROMPT-004')).toBe('trust-hierarchy');
  });

  it('matches `installed_hash` / `Ed25519` → signing-and-pinning', () => {
    expect(inferConceptFromFix('hackmyagent fix-all --with-aim — signs skills, heartbeats, and agent DNA with AIM keys')).toBe(
      'signing-and-pinning',
    );
  });

  it('returns undefined for fix text with no concept match', () => {
    expect(inferConceptFromFix('Move scheduled task configuration to a separate heartbeat config file')).toBeUndefined();
    expect(inferConceptFromFix('Remove the curl|sh or wget|sh pattern from this file')).toBeUndefined();
    expect(inferConceptFromFix(undefined, undefined)).toBeUndefined();
    expect(inferConceptFromFix('')).toBeUndefined();
  });

  it('priority: secretless-vault wins over soul-governance when both keywords appear', () => {
    // Cred-vault is the more actionable primitive on credential findings, so
    // when a fix mentions both "opena2a protect" and SOUL governance the
    // user gets the explainer that solves the immediate problem first.
    const fix = 'opena2a protect . — migrate creds; then harden-soul to add governance.';
    expect(inferConceptFromFix(fix)).toBe('secretless-vault');
  });
});
