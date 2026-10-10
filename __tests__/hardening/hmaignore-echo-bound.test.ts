/**
 * #937 — the `hmaignore` disclosure echoes a long `.hmaignore` line bounded.
 *
 * `secure --json` repeated every rule as written in `hmaignore.rules[].rule`,
 * and a path rule's text again in `path`, so a tree whose ignore file carried
 * one 4 MB line produced a report of more than 8 MB. Each field taken from the
 * line's text now stops at HMAIGNORE_ECHO_MAX characters and says how long the
 * text was. The rule itself is still applied in full.
 */
import { describe, it, expect } from 'vitest';
import {
  buildHmaIgnoreDisclosure,
  HMAIGNORE_ECHO_MAX,
  parseHmaIgnore,
  matchHmaIgnore,
} from '../../src/hardening/scanner';

const TODAY = '2026-01-15';

function parse(content: string) {
  return { present: true, file: '.hmaignore', ...parseHmaIgnore(content, TODAY) };
}

function disclose(content: string, matchedByLine: ReadonlyMap<number, number> = new Map()) {
  const disclosure = buildHmaIgnoreDisclosure(parse(content), matchedByLine);
  if (!disclosure) throw new Error('a present .hmaignore must produce a disclosure');
  return disclosure;
}

/** The echo of `text` when it is longer than the bound. */
function cutEcho(text: string): string {
  return `${text.slice(0, HMAIGNORE_ECHO_MAX)}… (${text.length} characters)`;
}

describe('#937 the hmaignore disclosure echoes a long line bounded', () => {
  it('a 4 MB path line is echoed in a few kilobytes, as rule and as path', () => {
    const line = `${'a'.repeat(4 * 1024 * 1024)}/`;
    const disclosure = disclose(`${line}\n`);

    expect(disclosure.rules).toHaveLength(1);
    const [rule] = disclosure.rules;
    expect(rule.channel).toBe('hmaignore-path');
    expect(rule.rule).toBe(cutEcho(line));
    expect(rule.path).toBe(cutEcho(line));
    expect(rule.rule).toMatch(/… \(4194305 characters\)$/);
    expect(JSON.stringify(disclosure).length).toBeLessThan(4 * HMAIGNORE_ECHO_MAX);
  });

  it('a long check pattern and a long reason are echoed bounded', () => {
    const pattern = `${'A'.repeat(3 * HMAIGNORE_ECHO_MAX)}-1`;
    const reason = 'r'.repeat(3 * HMAIGNORE_ECHO_MAX);
    const [checkRule, pathCheckRule] = disclose(`!${pattern}\nagent.py:NEMO-009 # ${reason}\n`).rules;

    expect(checkRule.checkId).toBe(cutEcho(pattern));
    expect(checkRule.rule).toBe(cutEcho(`!${pattern}`));
    expect(pathCheckRule.reason).toBe(cutEcho(reason));
    expect(pathCheckRule.path).toBe('agent.py');
    expect(pathCheckRule.checkId).toBe('NEMO-009');
  });

  it('a long refused line is echoed bounded in errors, rule and message alike', () => {
    const pattern = 'a.'.repeat(2 * HMAIGNORE_ECHO_MAX);
    const disclosure = disclose(`!${pattern}\n`);

    expect(disclosure.rules).toEqual([]);
    expect(disclosure.errors).toHaveLength(1);
    const [error] = disclosure.errors;
    expect(error.rule).toBe(cutEcho(`!${pattern}`));
    expect(error.error).toContain(`\`${cutEcho(pattern)}\` is not a check pattern`);
    expect(error.error.length).toBeLessThan(2 * HMAIGNORE_ECHO_MAX);
  });

  it('a long expires token and a long `<path>:*` prefix are named bounded in the error', () => {
    const token = `expires:${'9'.repeat(2 * HMAIGNORE_ECHO_MAX)}`;
    const prefix = 'p'.repeat(2 * HMAIGNORE_ECHO_MAX);
    const suffix = `A${'!'.repeat(2 * HMAIGNORE_ECHO_MAX)}*`;
    const { errors } = disclose(`agent.py ${token}\n${prefix}:*\nagent.py:${suffix}\n`);

    expect(errors.map((e) => e.line)).toEqual([1, 2, 3]);
    expect(errors[0].error).toContain(`\`${cutEcho(token)}\` is not a valid date`);
    expect(errors[1].error).toContain(`write \`${cutEcho(prefix)}\` to exclude the whole path`);
    expect(errors[2].error).toContain(`\`${cutEcho(suffix)}\` is a malformed check pattern`);
    for (const e of errors) expect(e.error.length).toBeLessThan(2 * HMAIGNORE_ECHO_MAX);
  });

  it('a line of exactly HMAIGNORE_ECHO_MAX characters is echoed as written, one more is cut', () => {
    const atBound = 'b'.repeat(HMAIGNORE_ECHO_MAX);
    const overBound = 'c'.repeat(HMAIGNORE_ECHO_MAX + 1);
    const [at, over] = disclose(`${atBound}\n${overBound}\n`).rules;

    expect(at.rule).toBe(atBound);
    expect(at.path).toBe(atBound);
    expect(over.rule).toBe(cutEcho(overBound));
  });

  it('does not end the echo on half of a surrogate pair', () => {
    const line = `${'d'.repeat(HMAIGNORE_ECHO_MAX - 1)}\u{1F600}${'d'.repeat(10)}`;
    const [rule] = disclose(`${line}\n`).rules;

    expect(rule.rule).toBe(`${'d'.repeat(HMAIGNORE_ECHO_MAX - 1)}… (${line.length} characters)`);
  });

  it('still applies a rule longer than the bound in full, and reports its match count', () => {
    const dir = 'nested/'.repeat(Math.ceil((2 * HMAIGNORE_ECHO_MAX) / 'nested/'.length));
    const content = `${dir}\n`;
    const parsed = parse(content);

    // A file under the full path is out of scope; a file that shares only
    // the echoed prefix is not.
    expect(matchHmaIgnore({ checkId: 'NEMO-009', file: `${dir}agent.py` }, parsed)).toEqual({
      channel: 'hmaignore-path',
      line: 1,
    });
    expect(
      matchHmaIgnore({ checkId: 'NEMO-009', file: `${dir.slice(0, HMAIGNORE_ECHO_MAX)}agent.py` }, parsed),
    ).toBeNull();

    const [rule] = disclose(content, new Map([[1, 3]])).rules;
    expect(rule.path).toBe(cutEcho(dir));
    expect(rule.matched).toBe(3);
  });
});
