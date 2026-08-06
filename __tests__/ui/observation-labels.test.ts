import { describe, it, expect } from 'vitest';
import {
  OBSERVATION_LABELS,
  OBSERVATION_LABEL_WIDTH,
} from '../../src/ui/quick-scan-labels';

/**
 * The Observations block pads each label to `OBSERVATION_LABEL_WIDTH` and
 * prints the value straight after. A label of exactly that width leaves no
 * separator, so the line renders as `Not examinedA2A, CVE, encryption`.
 *
 * That shipped twice inside one change — once as `Not examined`, once as
 * `Read no file`, both exactly 12 characters. It is invisible in review and
 * obvious to a user, which is the combination worth a test.
 */
describe('Observations block labels fit their column', () => {
  it('leaves at least one space after every label', () => {
    const entries = Object.entries(OBSERVATION_LABELS);
    expect(entries.length).toBeGreaterThan(0);
    for (const [key, label] of entries) {
      expect(
        label.length,
        `${key} ("${label}") is ${label.length} chars and needs to be under ${OBSERVATION_LABEL_WIDTH}`,
      ).toBeLessThan(OBSERVATION_LABEL_WIDTH);
      expect(label.padEnd(OBSERVATION_LABEL_WIDTH, ' ')).toMatch(/ $/);
    }
  });
});
