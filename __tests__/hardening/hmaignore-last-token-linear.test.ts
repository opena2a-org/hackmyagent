/**
 * #931 — a long `.hmaignore` line cannot stall the parser on its last token.
 *
 * Step (c) found the last token of a line with `text.match(/(\S+)\s*$/)`,
 * which retried the match at every non-space character: an 80,000-character
 * token followed by ` b` took seconds. The parser now scans from the end of
 * the line, and still peels `expires:` attributes off the end as before.
 */
import { describe, it, expect } from 'vitest';
import { parseHmaIgnore } from '../../src/hardening/scanner';

const TODAY = '2026-01-15';

describe('#931 the last token of a .hmaignore line is found in linear time', () => {
  it('parses an 80,000-character token followed by " b" within budget', () => {
    const line = `${'a'.repeat(80_000)} b`;
    const started = performance.now();
    parseHmaIgnore(`${line}\n`, TODAY);
    const elapsed = performance.now() - started;
    expect(elapsed, `took ${elapsed.toFixed(0)} ms`).toBeLessThan(250);
  });

  it('parses an 80,000-character token followed by an expires attribute within budget', () => {
    const line = `${'a'.repeat(80_000)} expires:2026-12-31`;
    const started = performance.now();
    parseHmaIgnore(`${line}\n`, TODAY);
    const elapsed = performance.now() - started;
    expect(elapsed, `took ${elapsed.toFixed(0)} ms`).toBeLessThan(250);
  });

  it('still takes the expires attributes from the end of the line', () => {
    const ok = parseHmaIgnore('docs/a.json expires:2026-12-31\t \n', TODAY);
    expect(ok.errors).toEqual([]);
    expect(ok.rules).toHaveLength(1);
    expect(ok.rules[0]).toMatchObject({ expires: '2026-12-31' });

    const twice = parseHmaIgnore('docs/a.json expires:2026-12-31 expires:2026-12-30\n', TODAY);
    expect(twice.rules).toEqual([]);
    expect(twice.errors[0].error).toMatch(/two `expires:` attributes/);

    const alone = parseHmaIgnore('expires:2026-12-31\n', TODAY);
    expect(alone.rules).toEqual([]);
    expect(alone.errors[0].error).toMatch(/needs a rule in front of it/);
  });
});
