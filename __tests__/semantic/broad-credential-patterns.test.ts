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
import {
  BROAD_CREDENTIAL_PATTERNS,
  CredentialContextAnalyzer,
} from '../../src/semantic/structural/credential-context';
import type { AnalysisFile } from '../../src/semantic/types';

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

  describe('the shared table carries no state between scans', () => {
    // Hoisting this table to module scope is a real behaviour change: it used
    // to be a local built fresh on every call, so each scan got its own RegExp
    // objects. Module-level `g`-flagged patterns are shared mutable state via
    // `lastIndex`, and a stale `lastIndex` makes `exec` start mid-line and skip
    // the credential at the front of the next file. The analyzer resets it per
    // pattern per line; these assertions are what hold that invariant in place.
    const analyzer = new CredentialContextAnalyzer();
    const file = (content: string): AnalysisFile =>
      ({ path: 'CLAUDE.md', type: 'agent_instructions', content, truncated: false } as AnalysisFile);

    it('finds a credential on a later line that sits LEFT of the previous match', () => {
      // The shape that actually bites, and the only one that does.
      //
      // Three obvious versions of this test were vacuous: repeating a scan,
      // scanning after a long REJECTED line, and asserting `lastIndex === 0`
      // after a scan. All three survive deleting the reset, because a `g`
      // regex whose `exec` returns null resets `lastIndex` to 0 by itself, and
      // the rejection path always ends in a null exec.
      //
      // The leak needs a line that MATCHES and breaks out early, leaving
      // `lastIndex` high, followed by a line whose credential begins at a LOWER
      // offset. Line 3 matches at roughly column 65; line 4's credential starts
      // at column 7, so a stale `lastIndex` starts `exec` past it and the
      // finding disappears. Verified: deleting `pattern.lastIndex = 0` drops
      // this from 2 findings to 1.
      const long = 'aB3xK9zQ7pR2mT8wY5vL4jH6nC1dF0sG' + 'X'.repeat(60);
      const content =
        '# Notes\n\n' +
        `some padding text here to push the match rightward, token = ${long}\n` +
        'key = aB3xK9zQ7pR2mT8wY5vL4jH6nC1dF0sG\n';
      const found = analyzer.analyze([file(content)]).filter((f) => f.id === 'SEM-CRED-003');
      expect(
        found.map((f) => f.line),
        'both credentials must be reported; a stale lastIndex silently drops the second',
      ).toEqual([3, 4]);
    });
  });
});
