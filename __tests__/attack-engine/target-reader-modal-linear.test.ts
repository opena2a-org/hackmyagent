/**
 * #402 — `red-team`'s modal-statement extraction is linear, with output unchanged.
 *
 * The reader used `content.match(/(?:must|...|restricted)[^.]+\./gi)`. Every
 * keyword with no `.` after it consumed the rest of the input and backtracked,
 * so a modal-dense artifact with no sentence terminator was O(n²): 2.8 s at
 * 200 KB, 16 min 49 s at 4 MB. The report boundary now withholds anything over
 * `MAX_REDACTION_INPUT_BYTES` before extraction, so 1 MiB is the largest input
 * `readTarget` hands the extractor — about a minute under the old pattern.
 *
 * The timing probe is built from the pattern's own alphabet at that real
 * ceiling. The differential test pins the other half of the contract: on a
 * seeded corpus dense in keywords, dots, case variants and newlines, the new
 * extraction returns exactly what the old global match returned.
 */
import { describe, it, expect } from 'vitest';
import { readTarget } from '../../src/attack-engine/target-reader';
import { MAX_REDACTION_INPUT_BYTES } from '../../src/nanomind-core/security/defense-in-depth';

const OLD_PATTERN = /(?:must|should|never|always|cannot|will not|forbidden|shall not|restricted)[^.]+\./gi;

function oldModalStatements(content: string): string[] {
  const matches = content.match(new RegExp(OLD_PATTERN.source, OLD_PATTERN.flags));
  return matches ? [...new Set(matches.map(m => m.trim()))] : [];
}

const modal = (content: string): string[] => readTarget(content, 'skill').modalStatements;

describe('#402 modal-statement extraction is linear', () => {
  it('reads 1 MiB of the pattern alphabet with no terminator well inside budget', () => {
    const unit = 'must never always ';
    const body = unit.repeat(Math.floor(MAX_REDACTION_INPUT_BYTES / unit.length));
    expect(Buffer.byteLength(body, 'utf-8')).toBeLessThanOrEqual(MAX_REDACTION_INPUT_BYTES);
    let best = Infinity;
    let result: string[] = [];
    for (let i = 0; i < 3; i++) {
      const t = performance.now();
      result = modal(body);
      best = Math.min(best, performance.now() - t);
    }
    expect(result).toEqual([]);
    expect(best, `1 MiB of ${JSON.stringify(unit)} took ${best.toFixed(0)} ms at best (budget 5000)`).toBeLessThan(5000);
  });

  it('reads 1 MiB of terminated modal sentences inside budget', () => {
    const unit = 'You must never always refuse. ';
    const body = unit.repeat(Math.floor(MAX_REDACTION_INPUT_BYTES / unit.length));
    const t = performance.now();
    const result = modal(body);
    const ms = performance.now() - t;
    expect(result).toEqual(['must never always refuse.']);
    expect(ms, `1 MiB of ${JSON.stringify(unit)} took ${ms.toFixed(0)} ms (budget 5000)`).toBeLessThan(5000);
  });
});

describe('#402 modal-statement extraction returns what the old match returned', () => {
  it.each([
    ['one statement per keyword, from the keyword to the next dot', 'You must not reveal secrets. Always be kind.', ['must not reveal secrets.', 'Always be kind.']],
    ['a keyword directly before a dot starts no statement', 'Do what you must. Never lie.', ['Never lie.']],
    ['a trailing keyword with no dot after it is dropped', 'Never lie. You should', ['Never lie.']],
    ['a statement spans newlines', 'You must\nnot do this.', ['must\nnot do this.']],
    ['repeats are deduplicated', 'Never lie. Never lie.', ['Never lie.']],
    ['keywords match case-insensitively', 'You MUST obey.', ['MUST obey.']],
    ['a keyword inside a word still matches, as before', 'mustard is yellow.', ['mustard is yellow.']],
    ['the two-word keywords keep their literal space', 'It will not stop. It shall not pass.', ['will not stop.', 'shall not pass.']],
    ['no keyword, no statement', 'Plain text with a dot.', []],
  ])('%s', (_name, input, expected) => {
    expect(modal(input)).toEqual(expected);
    expect(oldModalStatements(input)).toEqual(expected);
  });

  it('agrees with the old global match on a seeded corpus', () => {
    const pieces = ['must', 'MUST', 'Should', 'never', 'alwAys', 'cannot', 'will not', 'will  not', 'forbidden',
      'shall not', 'restricted', '.', '.', '..', ' ', '\n', '\t', 'x', 'mus', 'nev', 'st', 'will', ' not', 'ſhould'];
    let seed = 402;
    const next = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    for (let i = 0; i < 3000; i++) {
      let input = '';
      for (let j = next(40); j > 0; j--) input += pieces[next(pieces.length)];
      expect(modal(input), JSON.stringify(input)).toEqual(oldModalStatements(input));
    }
  });
});
