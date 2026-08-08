/**
 * #456 — the wording of the analyzer-family coverage disclosure.
 *
 * The load-bearing test here is the SILENCE one: a qualifier that always prints
 * is a constant, and a constant is not a measurement. Asserting only that the
 * text appears would stay green against `surfacesSuffix = ' (partial)'`.
 */

import { describe, it, expect } from 'vitest';
import { describeSemanticFamilyCoverage } from '../../src/ui/semantic-coverage-labels';
import type { SemanticFamilyCoverage } from '../../src/nanomind-core/scanner-bridge';

function coverage(over: Partial<SemanticFamilyCoverage> = {}): SemanticFamilyCoverage {
  return { totalFamilies: 7, artifactsCompiled: 1, fullyExamined: 0, partial: [], ...over };
}

describe('#456 describeSemanticFamilyCoverage', () => {
  describe('stays silent when there is nothing to disclose', () => {
    it('returns null when every compiled artifact reached all seven families', () => {
      // The negative control. An agent artifact examined by the whole suite
      // must produce NO qualifier — this is what proves the qualifier tracks a
      // measurement rather than printing unconditionally.
      expect(
        describeSemanticFamilyCoverage(coverage({ fullyExamined: 1, partial: [] })),
      ).toBeNull();
    });

    it('returns null when nothing was compiled', () => {
      expect(describeSemanticFamilyCoverage(coverage({ artifactsCompiled: 0 }))).toBeNull();
    });

    it('returns null when no ledger was supplied at all', () => {
      // An embedder calling the display helper directly supplies no ledger. The
      // line must stay silent rather than assert coverage built from nothing.
      expect(describeSemanticFamilyCoverage(undefined)).toBeNull();
    });
  });

  describe('names the shortfall when there is one', () => {
    it('reports 2 of 7 for an unknown document and names the five blind families', () => {
      const disclosure = describeSemanticFamilyCoverage(
        coverage({
          partial: [
            {
              artifactType: 'unknown',
              route: 'non_agent',
              familiesExamined: ['credentials', 'stego'],
              artifacts: 1,
              examplePaths: ['doc.md'],
            },
          ],
        }),
      );

      expect(disclosure).not.toBeNull();
      expect(disclosure!.surfacesSuffix).toContain('2 of 7 analyzer families');
      expect(disclosure!.surfacesSuffix).toContain(
        'capability, governance, scope, prompt and code analysis did not run',
      );
      expect(disclosure!.checksQualifier).toBe('2 of 7 analyzer families');
      // A partial route is the scanner's normal design. Colouring it would
      // leave the Surfaces line permanently yellow on real trees (measured: 26
      // of 30 artifacts) and dilute the file-cap warning sharing that line.
      expect(disclosure!.earnsWarningTone).toBe(false);
    });

    it('names a DIFFERENT blind set for source code at the same count', () => {
      const disclosure = describeSemanticFamilyCoverage(
        coverage({
          partial: [
            {
              artifactType: 'source_code',
              route: 'source_code',
              familiesExamined: ['credentials', 'code'],
              artifacts: 1,
              examplePaths: ['index.js'],
            },
          ],
        }),
      );

      // Same "2 of 7" as the document above. A hard-coded blind list would pass
      // that assertion in both cases and fail here: source code IS examined by
      // the code family, and is NOT examined by stego.
      expect(disclosure!.surfacesSuffix).toContain('2 of 7 analyzer families');
      expect(disclosure!.surfacesSuffix).toContain('steganography analysis did not run');
      expect(disclosure!.surfacesSuffix).not.toContain('code analysis did not run');
    });

    it('says no family looked when the artifact reached none', () => {
      const disclosure = describeSemanticFamilyCoverage(
        coverage({
          partial: [
            {
              artifactType: 'unknown',
              route: 'non_agent',
              familiesExamined: [],
              artifacts: 1,
              examplePaths: ['README.md'],
            },
          ],
        }),
      );

      // Stronger and shorter than listing all seven as absent.
      expect(disclosure!.surfacesSuffix).toContain('no analyzer family examined it');
      expect(disclosure!.checksQualifier).toBe('0 of 7 analyzer families');
      // The sharp case, and the only one that earns the colour.
      expect(disclosure!.earnsWarningTone).toBe(true);
    });

    it('reports a span, not an average, across mixed coverage', () => {
      const disclosure = describeSemanticFamilyCoverage(
        coverage({
          artifactsCompiled: 10,
          fullyExamined: 4,
          partial: [
            {
              artifactType: 'unknown',
              route: 'non_agent',
              familiesExamined: ['credentials', 'stego'],
              artifacts: 5,
              examplePaths: ['a.md'],
            },
            {
              artifactType: 'unknown',
              route: 'non_agent',
              familiesExamined: [],
              artifacts: 1,
              examplePaths: ['README.md'],
            },
          ],
        }),
      );

      // A mean would let the four fully-examined artifacts pay for the one
      // nothing looked at.
      expect(disclosure!.surfacesSuffix).toContain('6 of 10 artifacts');
      // Its own segment, not a second parenthetical colliding with the
      // file-cap notice that shares this line.
      expect(disclosure!.surfacesSuffix.startsWith(' \u00b7 ')).toBe(true);
      expect(disclosure!.surfacesSuffix).not.toContain('(');
      expect(disclosure!.surfacesSuffix).toContain('0-2 of 7 analyzer families');
      expect(disclosure!.surfacesSuffix).not.toMatch(/%/);
      // Compact on the Checks line: the artifact count lives on Surfaces.
      //
      // `0-7`, not `0-2`. This fixture has fullyExamined: 4, and the Checks
      // qualifier describes the whole compiled set, so the four artifacts that
      // reached all seven are part of its range. The first version of this
      // assertion said `0-2` because it was written from what the code printed
      // rather than from what was true of the ten artifacts — which is how the
      // understatement survived its own test.
      expect(disclosure!.checksQualifier).toBe('0-7 of 7 analyzer families');
      expect(disclosure!.earnsWarningTone).toBe(true);
    });

    it('the Checks span covers the WHOLE compiled set, including the fully examined', () => {
      // The Checks qualifier hangs off `N semantic (NanoMind AST, …)` with no
      // subject, so it describes every compiled artifact. Computing its span from
      // the shortfall classes alone made it understate: a tree where 4 of 30
      // artifacts reached all seven printed `0-6 of 7` for all 30, contradicting
      // the Surfaces line one row above.
      const disclosure = describeSemanticFamilyCoverage(
        coverage({
          artifactsCompiled: 30,
          fullyExamined: 4,
          partial: [
            { artifactType: 'unknown', route: 'non_agent', familiesExamined: ['credentials', 'stego'], artifacts: 20, examplePaths: ['a.md'] },
            { artifactType: 'soul', route: 'agent', familiesExamined: ['capabilities', 'credentials', 'governance', 'scope', 'prompt', 'stego'], artifacts: 6, examplePaths: ['SOUL.md'] },
          ],
        }),
      );

      // Whole set: 0..7 is wrong too — nothing here reached 0 — so it must be 2-7.
      expect(disclosure!.checksQualifier).toBe('2-7 of 7 analyzer families');
      // Surfaces keeps its own subject and its own span over the shortfall.
      expect(disclosure!.surfacesSuffix).toContain('26 of 30 artifacts');
      expect(disclosure!.surfacesSuffix).toContain('2-6 of 7 analyzer families');
      // Mixed coverage where the WORST class still reached 2 families: every
      // artifact was read by something, so this does not earn the colour. Without
      // this assertion the mixed branch had no case where the tone must be false,
      // and hard-coding `earnsWarningTone: true` there survived mutation.
      expect(disclosure!.earnsWarningTone).toBe(false);
    });

    it('says "all N" when every compiled artifact falls short', () => {
      // The usual case on a large repo: this repo's own self-scan has all 200
      // compiled artifacts short of the full suite, where `200 of 200` reads
      // worse than `all 200`.
      const disclosure = describeSemanticFamilyCoverage(
        coverage({
          artifactsCompiled: 200,
          fullyExamined: 0,
          partial: [
            { artifactType: 'source_code', route: 'source_code', familiesExamined: ['credentials', 'code'], artifacts: 150, examplePaths: ['a.ts'] },
            { artifactType: 'unknown', route: 'non_agent', familiesExamined: [], artifacts: 50, examplePaths: ['README.md'] },
          ],
        }),
      );

      expect(disclosure!.surfacesSuffix).toContain('all 200 artifacts');
      expect(disclosure!.surfacesSuffix).not.toContain('200 of 200');
      expect(disclosure!.surfacesSuffix).toContain('0-2 of 7 analyzer families');
    });

    it('uses "each" rather than "it" when a class holds several artifacts', () => {
      const disclosure = describeSemanticFamilyCoverage(
        coverage({
          artifactsCompiled: 3,
          partial: [
            {
              artifactType: 'unknown',
              route: 'non_agent',
              familiesExamined: ['credentials', 'stego'],
              artifacts: 3,
              examplePaths: ['a.md', 'b.md', 'c.md'],
            },
          ],
        }),
      );

      expect(disclosure!.surfacesSuffix).toContain('examined each');
    });
  });

  it('prints nothing rather than a self-contradicting number', () => {
    // Not reachable from the bridge, but this reads a public type. A ledger whose
    // own fields disagree must produce no claim at all: "5 of 3 analyzer
    // families" is not a measurement.
    expect(
      describeSemanticFamilyCoverage(
        coverage({
          totalFamilies: 3,
          partial: [
            { artifactType: 'unknown', route: 'non_agent', familiesExamined: ['a', 'b', 'c', 'd', 'e'] as never, artifacts: 1, examplePaths: ['x'] },
          ],
        }),
      ),
    ).toBeNull();
    expect(
      describeSemanticFamilyCoverage(
        coverage({
          artifactsCompiled: 1,
          fullyExamined: 2,
          partial: [
            { artifactType: 'unknown', route: 'non_agent', familiesExamined: ['credentials'], artifacts: 1, examplePaths: ['x'] },
          ],
        }),
      ),
    ).toBeNull();
    expect(describeSemanticFamilyCoverage(coverage({ totalFamilies: -3 }))).toBeNull();
  });

  it('never implies a defect in the scanned tree', () => {
    const disclosure = describeSemanticFamilyCoverage(
      coverage({
        partial: [
          {
            artifactType: 'unknown',
            route: 'non_agent',
            familiesExamined: ['credentials', 'stego'],
            artifacts: 1,
            examplePaths: ['doc.md'],
          },
        ],
      }),
    );

    // A coverage qualifier is a statement about the scan, not an accusation
    // about the target. #456 is explicit that it must add no finding.
    for (const word of ['CRITICAL', 'HIGH', 'vulnerable', 'insecure', 'risk']) {
      expect(disclosure!.surfacesSuffix.toLowerCase()).not.toContain(word.toLowerCase());
    }
  });
});
