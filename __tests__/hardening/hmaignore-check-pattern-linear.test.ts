/**
 * #926 — a `.hmaignore` check pattern with many `*` cannot stall a scan.
 *
 * The matcher turned every `*` into `.*` and the grammar accepts any number
 * of them, so `!` followed by a run of stars and one letter backtracked on
 * every finding it was compared with: one comparison of a 12-star pattern
 * with `SEM-LLM-NOT-ANALYZED` took seconds, and `secure` with a 24-star line
 * did not answer within a minute.
 *
 * The timing row grows the pattern one star at a time and stops at the first
 * comparison over budget, so the expression the matcher used to build fails
 * it within a second or two instead of hanging the runner. The table rows pin
 * that the scan in order answers what that expression answered.
 */
import { describe, it, expect } from 'vitest';
import { matchesCheckPattern } from '../../src/hardening/scanner';
import { parseHmaIgnore, matchHmaIgnore } from '../../src/index';

const TODAY = '2026-01-15';
const ID = 'SEM-LLM-NOT-ANALYZED';

/** What the matcher answered before #926, for the equivalence rows. */
function viaExpression(checkId: string, pattern: string): boolean {
  const p = pattern.toUpperCase();
  const source = '^' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
  return new RegExp(source).test(checkId.toUpperCase());
}

describe('#926 check patterns match in time linear in their length', () => {
  it('compares a pattern of up to 30 stars and one letter within budget', () => {
    const budgetMs = 250;
    for (let stars = 1; stars <= 30; stars++) {
      const line = `!${'*'.repeat(stars)}X`;
      const parsed = { present: true, file: '.hmaignore', ...parseHmaIgnore(`${line}\n`, TODAY) };
      // The grammar accepts the line, so the matcher sees it.
      expect(parsed.errors).toEqual([]);
      expect(parsed.rules).toHaveLength(1);

      const started = performance.now();
      const match = matchHmaIgnore({ checkId: ID, file: 'agent.py' }, parsed);
      const elapsed = performance.now() - started;

      expect(match, `${stars} stars`).toBeNull();
      expect(elapsed, `${stars} stars took ${elapsed.toFixed(0)} ms`).toBeLessThan(budgetMs);
    }
  });

  it('still matches a 30-star pattern whose pieces appear in order', () => {
    const pattern = `${'*'.repeat(10)}SEM${'*'.repeat(10)}NOT${'*'.repeat(10)}`;
    expect(matchesCheckPattern(ID, pattern)).toBe(true);
    expect(matchesCheckPattern(ID, `${'*'.repeat(10)}NOT${'*'.repeat(10)}SEM${'*'.repeat(10)}`)).toBe(false);
  });

  const rows: Array<[string, string, boolean]> = [
    ['NEMO-009', 'NEMO-009', true],
    ['NEMO-009', 'nemo-009', true],
    ['nemo-009', 'NEMO-*', true],
    ['NEMO-009', 'NEMO-*', true],
    ['NEMO-009', '*-009', true],
    ['NEMO-009', '*', true],
    ['NEMO-009', '***', true],
    ['NEMO-009', 'N*M*-0*9', true],
    ['NEMO-009', 'NEMO-009*', true],
    ['NEMO-009', '*NEMO-009', true],
    ['NEMO-009', 'NEMO**009', true],
    ['NEMO-009', 'NEMO-01*', false],
    ['NEMO-009', '*-010', false],
    ['NEMO-009', 'NEMO', false],
    ['NEMO-009', 'NEMO-0', false],
    // Prefix and suffix may not share characters.
    ['ABA', 'AB*BA', false],
    ['ABBA', 'AB*BA', true],
    ['A', 'A*A', false],
    ['AA', 'A*A', true],
    // A middle piece may not run into the suffix.
    ['SEM-X', '*SEM*-X*X', false],
    [ID, '*LLM*ANALYZED', true],
    [ID, '*LLM*LLM*', false],
    [ID, 'SEM-*-*-*', true],
    [ID, 'SEM-*-*-*-*', false],
  ];

  it.each(rows)('%s against %s is %s', (checkId, pattern, expected) => {
    expect(matchesCheckPattern(checkId, pattern)).toBe(expected);
    expect(viaExpression(checkId, pattern)).toBe(expected);
  });

  it('answers what the expression answered for every pattern of up to five of A, B, - and *', () => {
    const ids = ['A', 'AB', 'ABA', 'AAB', 'BAA', 'ABAB', 'A-B', 'AB-AB'];
    const alphabet = ['A', 'B', '-', '*'];
    let compared = 0;
    for (let length = 1; length <= 5; length++) {
      const total = alphabet.length ** length;
      for (let n = 0; n < total; n++) {
        let pattern = '';
        for (let k = 0, rest = n; k < length; k++, rest = Math.floor(rest / alphabet.length)) {
          pattern += alphabet[rest % alphabet.length];
        }
        for (const id of ids) {
          expect(matchesCheckPattern(id, pattern), `${id} against ${pattern}`).toBe(viaExpression(id, pattern));
          compared++;
        }
      }
    }
    expect(compared).toBe(ids.length * (4 + 16 + 64 + 256 + 1024));
  });

  it('matches nothing for an empty id or an empty pattern', () => {
    expect(matchesCheckPattern('', '*')).toBe(false);
    expect(matchesCheckPattern('NEMO-009', '')).toBe(false);
  });
});
