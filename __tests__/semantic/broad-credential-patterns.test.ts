/**
 * Structural gate on the SEM-CRED-003 pattern table.
 *
 * `requiresEntropy: true` means "the filler test is applied to capture group 1
 * of this pattern". If a pattern is ever marked that way without a capture
 * group, the value is `undefined` and the floor cannot be applied.
 *
 * That used to `throw` from inside the per-line loop, which was the worst
 * available failure mode: `scanner.ts` wraps the whole structural pass in a
 * bare `catch` ("Structural analysis failure is non-fatal"), so the throw
 * deleted all four Layer 2 analyzers, produced no findings at all, and
 * IMPROVED the reported score. A silent detection loss that also looks like a
 * pass is worse than any false positive.
 *
 * The runtime now fails CLOSED (a missing capture is treated as a credential),
 * and this file is the real guarantee: the defect is caught in CI, at the
 * table, before it can reach a scan. TypeScript can enforce that `valueGroup`
 * only exists when `requiresEntropy` is true, but it cannot inspect a RegExp
 * literal for capture groups — that is what these assertions are for.
 */

import { describe, it, expect } from 'vitest';
import { BROAD_CREDENTIAL_PATTERNS } from '../../src/semantic/structural/credential-context';

describe('SEM-CRED-003 broad credential pattern table', () => {
  it('is not empty (guards against a vacuous sweep below)', () => {
    expect(BROAD_CREDENTIAL_PATTERNS.length).toBeGreaterThan(0);
    expect(
      BROAD_CREDENTIAL_PATTERNS.filter((p) => p.requiresEntropy).length,
      'at least one pattern must be entropy-gated, or these assertions test nothing',
    ).toBeGreaterThan(0);
  });

  it('gives every entropy-gated pattern a real capture group', () => {
    for (const pattern of BROAD_CREDENTIAL_PATTERNS) {
      if (!pattern.requiresEntropy) continue;
      // `(?:` groups do not count. Compile a probe that matches the empty
      // string and read the resulting group count off the match: appending
      // `|(?:)` makes the alternation always succeed without adding a group.
      const probe = new RegExp(`${pattern.pattern.source}|(?:)`);
      const groups = probe.exec('')!.length - 1;
      expect(
        groups,
        `pattern "${pattern.name}" is marked requiresEntropy but exposes ${groups} capture groups`,
      ).toBeGreaterThanOrEqual(1);
    }
  });

  it('captures the VALUE, not the key descriptor, in group 1', () => {
    // Capturing the whole match would feed `password:` into the filler test
    // and make the floor a no-op, which is the failure this table's contract
    // exists to prevent. Assert the captured text on a representative line.
    const blank = '_'.repeat(47);
    for (const pattern of BROAD_CREDENTIAL_PATTERNS) {
      if (!pattern.requiresEntropy) continue;
      const re = new RegExp(pattern.pattern.source, pattern.pattern.flags.replace('g', ''));
      const m = re.exec(`password: ${blank}`);
      if (!m) continue; // not every entropy pattern matches every shape
      expect(
        m[1],
        `pattern "${pattern.name}" must capture the value, not "${m[0]}"`,
      ).toBe(blank);
      expect(m[1], 'the capture must not carry the key descriptor').not.toContain('password');
    }
  });

  it('declares valueGroup 1 wherever it declares requiresEntropy', () => {
    for (const pattern of BROAD_CREDENTIAL_PATTERNS) {
      if (pattern.requiresEntropy) {
        expect(pattern.valueGroup, `pattern "${pattern.name}"`).toBe(1);
      }
    }
  });

  it('keeps every pattern global, since the analyzer walks all matches per line', () => {
    // The per-line loop calls `pattern.exec` repeatedly and resets
    // `lastIndex`. A non-global pattern would restart from 0 every time and
    // loop forever on any line with a rejected match.
    for (const pattern of BROAD_CREDENTIAL_PATTERNS) {
      expect(pattern.pattern.flags, `pattern "${pattern.name}"`).toContain('g');
    }
  });
});
