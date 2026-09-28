/**
 * #645 — `SEMANTIC_OASB_MAPPINGS` is library API with no in-tree consumer; the
 * assessor reads the catalogue in `src/benchmarks/oasb-1.ts`. So the export
 * may only restate the catalogue: every check it lists for a control must be
 * one the catalogue maps to that control. It listed `SEM-CRED-002` for 5.2,
 * which the catalogue verifies with `MCP-006` and `MCP-009`, telling a library
 * consumer 5.2 is verified by a check the assessor never reads for it.
 */
import { describe, it, expect } from 'vitest';
import {
  SEMANTIC_OASB_MAPPINGS,
  getSemanticCheckIds,
  getUpgradedControlIds,
} from '../../src/semantic/integration/oasb-upgrader';
import { OASB_1_CATEGORIES } from '../../src/benchmarks/oasb-1';

const catalogue = new Map(
  OASB_1_CATEGORIES.flatMap((c) => c.controls).map((c) => [c.id, c.checkIds] as const),
);

describe('#645 SEMANTIC_OASB_MAPPINGS restates the catalogue and nothing else', () => {
  for (const [controlId, checkIds] of Object.entries(SEMANTIC_OASB_MAPPINGS)) {
    it(`${controlId}: every listed check is in the catalogue's checkIds for ${controlId}`, () => {
      expect(catalogue.has(controlId), `${controlId} is not an OASB-1 control`).toBe(true);
      const missing = checkIds.filter((id) => !(catalogue.get(controlId) ?? []).includes(id));
      expect(missing).toEqual([]);
    });
  }

  it('lists no control with an empty entry, and the helpers read the same map', () => {
    for (const id of getUpgradedControlIds()) {
      expect(getSemanticCheckIds(id).length, id).toBeGreaterThan(0);
      expect(getSemanticCheckIds(id)).toEqual(SEMANTIC_OASB_MAPPINGS[id]);
    }
    expect(getUpgradedControlIds().sort()).toEqual(Object.keys(SEMANTIC_OASB_MAPPINGS).sort());
  });
});
