/**
 * The three defects the adversarial pass found in the rendering layer itself.
 *
 * All of them are cases where the new rule was STRICTER than the property it was
 * written to enforce, so a path a command names perfectly well got a dead end
 * and a false sentence about why.
 */
import { describe, it, expect } from 'vitest';
import { escapeForDisplay, escapePathForDisplay, hasDisplayHazard } from '../../src/ui/display-safe';
import { citationPath } from '../../src/ui/shell-quote';

describe('rendering a path the reader can act on', () => {
  /**
   * The pictograph exemption is a lookbehind, and `escapePathForDisplay` tested
   * one code point at a time, so the lookbehind never saw what preceded it.
   * Every variation selector was escaped, `❤️.txt` rendered `❤️.txt`, and
   * `citationPath` then refused to name it — the exact outcome the exemption
   * exists to prevent, in the one function that renders a bare filename.
   */
  it('leaves an emoji presentation selector alone in a bare path', () => {
    const name = '❤️-notes.md';
    expect(escapeForDisplay(name), 'the whole-string escape lost the exemption').toBe(name);
    expect(
      escapePathForDisplay(name),
      'the bare-path escape mangles an emoji filename that the composed-text escape leaves alone',
    ).toBe(name);
    expect(
      citationPath(name),
      'an emoji filename got no command, so the report is a dead end for it',
    ).toBe(`'${name}'`);
  });

  /**
   * A variation selector that follows nothing visible is still concealment, and
   * still escaped — without this the exemption above could be "never escape a
   * selector".
   */
  it('still escapes a variation selector that modifies nothing visible', () => {
    const name = `a${'️'}b.txt`;
    expect(escapePathForDisplay(name)).toBe('a\\ufe0fb.txt');
    expect(citationPath(name), 'a concealed path was given a pasteable command').toBeNull();
  });

  /**
   * `escapePathForDisplay(p) !== p` was the wrong predicate for "no command can
   * name this". For `a\test.json` the only difference is this module's own
   * backslash doubling, and `rm 'a\test.json'` is correct — the previous build
   * emitted it, and the first version of this change replaced it with a dead end
   * plus the false claim that the name "carries characters a pasted command
   * cannot name".
   */
  it('still names a path whose only rendering difference is backslash doubling', () => {
    expect(escapePathForDisplay('a\\test.json')).toBe('a\\\\test.json');
    expect(hasDisplayHazard('a\\test.json'), 'a backslash is not a display hazard').toBe(false);
    expect(citationPath('a\\test.json')).toBe("'a\\test.json'");
    // And the reported #347.5 case still renders identically in both halves.
    expect(escapePathForDisplay('a\\b.txt')).toBe('a\\b.txt');
    expect(citationPath('a\\b.txt')).toBe("'a\\b.txt'");
  });

  /** A real hazard still gets no command — the #343 rule is unchanged. */
  it('gives no command to a path carrying a control character', () => {
    expect(citationPath('nl\nsecond')).toBeNull();
    expect(citationPath(`x${String.fromCodePoint(0x202e)}y`)).toBeNull();
  });

  /**
   * #340, second instance: zsh expands a leading `=` to a resolved command
   * path, so `rm =python3` deleted a binary while the report displayed a project
   * file. `sh` does not, which is why the property test could not see it.
   */
  it('quotes a path zsh would expand', () => {
    expect(citationPath('=python3'), 'a zsh EQUALS expansion was emitted unquoted')
      .toBe("'=python3'");
  });

  /** Injectivity, still: two different names never render identically. */
  it('renders backslash-escape pairs distinguishably', () => {
    expect(escapePathForDisplay('dir\\nx')).not.toBe(escapePathForDisplay('dir\nx'));
  });
});
