/**
 * The `.hmaignore` grammar is importable from the package root.
 *
 * A dependent tool that honours the same file has to read it with the same
 * parser, the same tier order and the same scope/presentational split, or the
 * two tools disagree about which findings leave the exit code. These rows
 * import the parser, the matcher and the scope predicate from the root, the
 * path a dependent package resolves, and walk one rule of each kind through
 * all three.
 *
 * Fixture text only: nothing here reads a file.
 */
import { describe, it, expect } from 'vitest';
import { parseHmaIgnore, matchHmaIgnore, isScopeChannel } from '../../src/index';
import type {
  HmaIgnoreRule,
  HmaIgnoreParseError,
  ParsedHmaIgnore,
  HmaIgnoreMatch,
  HmaIgnoreFinding,
  ScopeChannel,
  PresentationalChannel,
  SuppressionChannel,
} from '../../src/index';

const TODAY = '2026-01-15';

function parse(content: string): ParsedHmaIgnore {
  const parsed: { rules: HmaIgnoreRule[]; errors: HmaIgnoreParseError[] } = parseHmaIgnore(content, TODAY);
  return { present: true, file: '.hmaignore', ...parsed };
}

describe('.hmaignore grammar from the package root', () => {
  it('exports the three functions', () => {
    expect(typeof parseHmaIgnore).toBe('function');
    expect(typeof matchHmaIgnore).toBe('function');
    expect(typeof isScopeChannel).toBe('function');
  });

  it('parses `<path>:<CHECK-ID> # reason` to a scope rule the matcher honours', () => {
    const parsed = parse('danger.py:NEMO-009 # fixture, never shipped\n');
    expect(parsed.errors).toEqual([]);
    expect(parsed.rules).toHaveLength(1);

    const rule: HmaIgnoreRule = parsed.rules[0];
    expect(rule.channel).toBe('hmaignore-path-check');
    expect(rule.path).toBe('danger.py');
    expect(rule.checkId).toBe('NEMO-009');
    expect(rule.reason).toBe('fixture, never shipped');
    expect(isScopeChannel(rule.channel)).toBe(true);

    const finding: HmaIgnoreFinding = { checkId: 'NEMO-009', file: 'danger.py' };
    const match: HmaIgnoreMatch | null = matchHmaIgnore(finding, parsed);
    expect(match).toEqual({ channel: 'hmaignore-path-check', line: 1 });

    // The rule is narrowed to its path and to its check.
    expect(matchHmaIgnore({ checkId: 'NEMO-009', file: 'other.py' }, parsed)).toBeNull();
    expect(matchHmaIgnore({ checkId: 'NEMO-010', file: 'danger.py' }, parsed)).toBeNull();
  });

  it('parses `!<CHECK-ID>` to a presentational rule', () => {
    const parsed = parse('!NEMO-009\n');
    expect(parsed.errors).toEqual([]);
    expect(parsed.rules).toHaveLength(1);

    const rule: HmaIgnoreRule = parsed.rules[0];
    expect(rule.channel).toBe('hmaignore-check');
    expect(rule.checkId).toBe('NEMO-009');
    expect(rule.path).toBeUndefined();
    expect(isScopeChannel(rule.channel)).toBe(false);

    const match = matchHmaIgnore({ checkId: 'NEMO-009', file: 'danger.py' }, parsed);
    expect(match).toEqual({ channel: 'hmaignore-check', line: 1 });
    expect(match !== null && isScopeChannel(match.channel)).toBe(false);
  });

  it('answers the scope question for every channel in the union', () => {
    const scope: ScopeChannel[] = ['hmaignore-path', 'hmaignore-path-check'];
    const presentational: PresentationalChannel[] = ['ignore-flag', 'hmaignore-check'];
    const all: SuppressionChannel[] = [...scope, ...presentational];

    expect(all.filter((ch) => isScopeChannel(ch))).toEqual(scope);
    expect(all.filter((ch) => !isScopeChannel(ch))).toEqual(presentational);
  });
});
