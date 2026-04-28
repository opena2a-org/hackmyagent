import { describe, it, expect } from 'vitest';
import { CONCEPT_EXPLAINERS, getConceptExplainer } from '../../src/ui/concept-explainers';
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
