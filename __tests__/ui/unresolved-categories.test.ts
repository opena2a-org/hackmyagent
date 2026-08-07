// #421 — the backstop that stops a category reporting `clear` while holding a
// detection nobody was shown.
//
// Tested here rather than end-to-end on purpose. Firing it needs a project that
// BOTH trips one of the 23 narrow-scoped checks that emit a file AND is not
// detected as the project type that check belongs to — and those two conditions
// pull against each other (a tree with an MCP config tends to be detected as
// `mcp`). No natural fixture was found, and a guard that cannot be
// distinguished from its absence is not a guard, so the logic was split out of
// `cli.ts` and is exercised directly.

import { describe, it, expect } from 'vitest';
import {
  suppressedCategoryLabels,
  unresolvedCategoryNames,
  type SuppressedFailureIdentity,
} from '../../src/ui/unresolved-categories';

function silenced(
  checkId: string,
  category: string,
  name = `${checkId} finding`,
): SuppressedFailureIdentity {
  return { checkId, name, category, severity: 'high' };
}

describe('suppressedCategoryLabels', () => {
  it('is empty when nothing was silenced', () => {
    expect(suppressedCategoryLabels([]).size).toBe(0);
  });

  // THE POINT OF THE FUNCTION. The scanner records a finding's own `category`,
  // but the renderer buckets by check-ID prefix into a DIFFERENT vocabulary.
  // Keying the backstop off the raw field matches only the handful of names
  // that coincide, and every other category goes on claiming `clear` while
  // hiding a detection — the original bug, one layer along.
  it.each([
    // Every expected label here is the classifier's MEASURED answer, not a
    // reading of the prefix table: `SEC-001` lands in `credentials` (a keyword
    // rule fires before the `SEC` prefix rule) and `GATEWAY-001` in `network`.
    // Both were guessed wrong first and corrected against the real output.
    ['LOG-002', 'logging', 'audit'],
    ['SESSION-003', 'session-security', 'session'],
    ['SEC-001', 'secrets', 'credentials'],
    ['INJ-003', 'input-validation', 'injection'],
    ['GATEWAY-001', 'gateway', 'network'],
  ])('buckets %s (category %s) under the renderer label %s', (checkId, category, label) => {
    const labels = suppressedCategoryLabels([silenced(checkId, category)]);
    expect([...labels]).toEqual([label]);
    expect(labels.has(label)).toBe(true);
  });

  it('maps a check whose raw category is not a renderer label at all', () => {
    // `session-security` is not in ALL_CATEGORY_LABELS; a raw-keyed lookup can
    // never match it, so this is the case that silently did nothing.
    const labels = suppressedCategoryLabels([silenced('SESSION-001', 'session-security')]);
    expect(labels.has('session-security')).toBe(false);
    expect(labels.has('session')).toBe(true);
  });

  it('collapses several silenced checks in one category to a single label', () => {
    const labels = suppressedCategoryLabels([
      silenced('LOG-002', 'logging'),
      silenced('AUDIT-004', 'audit'),
    ]);
    expect([...labels]).toEqual(['audit']);
  });
});

describe('unresolvedCategoryNames', () => {
  const summaries = [
    { name: 'audit', clear: true },
    { name: 'credentials', clear: true },
    { name: 'git hygiene', clear: false },
    { name: 'network', clear: true },
  ];
  const examinedAlways = () => true;

  it('withdraws clear from an examined category holding a silenced detection', () => {
    const names = unresolvedCategoryNames(
      summaries,
      examinedAlways,
      suppressedCategoryLabels([silenced('LOG-002', 'logging')]),
    );
    expect(names).toEqual(['audit']);
  });

  it('leaves a category alone when nothing in it was silenced', () => {
    expect(unresolvedCategoryNames(summaries, examinedAlways, new Set())).toEqual([]);
  });

  // A category already showing a finding needs no correction — it is not
  // claiming to be clear, so withdrawing anything would double-report it.
  it('never names a category that is already reporting a finding', () => {
    const names = unresolvedCategoryNames(
      summaries,
      examinedAlways,
      new Set(['git hygiene']),
    );
    expect(names).toEqual([]);
  });

  // An unexamined category is already disclosed on the `Unexamined` line.
  it('never names a category the run did not examine', () => {
    const names = unresolvedCategoryNames(
      summaries,
      name => name !== 'audit',
      suppressedCategoryLabels([silenced('LOG-002', 'logging')]),
    );
    expect(names).toEqual([]);
  });

  // Without a coverage ledger the caller passes an always-false predicate,
  // because the disclosure line cannot render. Withdrawing `clear` there would
  // trade a false claim for an unexplained gap, which is the failure this
  // whole change exists to prevent.
  it('withdraws nothing when the run has no coverage ledger', () => {
    const names = unresolvedCategoryNames(
      summaries,
      () => false,
      suppressedCategoryLabels([silenced('LOG-002', 'logging')]),
    );
    expect(names).toEqual([]);
  });

  it('names every qualifying category, in summary order', () => {
    const names = unresolvedCategoryNames(
      summaries,
      examinedAlways,
      suppressedCategoryLabels([
        silenced('LOG-002', 'logging'),
        silenced('NET-001', 'network'),
      ]),
    );
    expect(names).toEqual(['audit', 'network']);
  });
});
