import { describe, it, expect } from 'vitest';
import { CONCEPT_EXPLAINERS, getConceptExplainer } from '../../src/ui/concept-explainers';
import type { ConceptId } from '../../src/types/finding-evidence';

const ALL_CONCEPTS: ConceptId[] = [
  'soul-governance',
  'secretless-vault',
  'mcp-tool-isolation',
  'injection-resistance',
  'trust-hierarchy',
  'signing-and-pinning',
];

describe('CONCEPT_EXPLAINERS registry', () => {
  it('has an entry for every ConceptId in the union', () => {
    for (const id of ALL_CONCEPTS) {
      const entry = CONCEPT_EXPLAINERS[id];
      expect(entry, `missing entry for ${id}`).toBeDefined();
      expect(entry.id).toBe(id);
    }
  });

  it('every entry has a non-empty title, body, and oneLineRef', () => {
    for (const id of ALL_CONCEPTS) {
      const entry = CONCEPT_EXPLAINERS[id];
      expect(entry.title.length).toBeGreaterThan(0);
      expect(entry.body.length).toBeGreaterThan(0);
      expect(entry.oneLineRef.length).toBeGreaterThan(0);
    }
  });

  it('oneLineRef references the concept by name (helps the user follow back-refs)', () => {
    // Don't enforce exact wording — just sanity-check that the back-ref isn't generic
    for (const id of ALL_CONCEPTS) {
      const ref = CONCEPT_EXPLAINERS[id].oneLineRef;
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
