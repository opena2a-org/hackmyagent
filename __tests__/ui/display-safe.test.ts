/**
 * #324 — control characters in a path must not reach a rendered line.
 *
 * The measured defect: a directory whose name contained a newline produced
 *
 *     Fix: rm -rf '/…/.hackmyagent-backup/2026-01-01-000000
 *
 * The emitted command was correct — `shellQuote` is total and executing the
 * argument removed the right directory — but the renderer keeps only the first
 * non-blank line, so the visible command ended mid-quote and pasting it left the
 * shell at a `quote>` continuation prompt.
 *
 * Control characters are written as `\x`/`\u` escapes or built with
 * `String.fromCodePoint` throughout. A raw control byte in a test fixture is
 * invisible in review and, for NUL, silently truncates the line it sits on.
 */
import { describe, it, expect } from 'vitest';
import { escapeForDisplay, escapePathForDisplay } from '../../src/ui/display-safe';

const ESC = String.fromCodePoint(0x1b);
const NUL = String.fromCodePoint(0x00);

describe('escapeForDisplay', () => {
  it('leaves ordinary text byte-identical', () => {
    // The common case by far. If this changed, every rendered line in the tool
    // would change with it.
    const plain = "rm -rf '/home/me/proj/.hackmyagent-backup/2026-01-01-000000'";
    expect(escapeForDisplay(plain)).toBe(plain);
  });

  it('makes a newline visible instead of dropping it', () => {
    const withNewline = "rm -rf '/p/2026-01-01-000000\nEVIL'";
    const out = escapeForDisplay(withNewline);
    expect(out).toBe("rm -rf '/p/2026-01-01-000000\\nEVIL'");
    // The point of the exercise: one line, and the quote closes.
    expect(out.split('\n')).toHaveLength(1);
    expect(out.endsWith("'")).toBe(true);
  });

  it('escapes the named control characters readably', () => {
    expect(escapeForDisplay('a\rb')).toBe('a\\rb');
    expect(escapeForDisplay('a\tb')).toBe('a\\tb');
    expect(escapeForDisplay(`a${ESC}b`)).toBe('a\\eb');
    expect(escapeForDisplay(`a${NUL}b`)).toBe('a\\0b');
  });

  it('neutralizes an ANSI escape sequence', () => {
    // A path is attacker-influenced data. `ESC [ 2 J` clears the terminal, and a
    // CSI sequence can overwrite the lines above it — a path that edits the
    // report describing it.
    const out = escapeForDisplay(`${ESC}[2Jcleared`);
    expect(out).toBe('\\e[2Jcleared');
    expect(out).not.toContain(ESC);
  });

  it('is total over every character it claims to cover', () => {
    // Not a sample: every C0, DEL, C1 and both Unicode line separators, checked
    // for the property that matters — nothing in the output can move a cursor,
    // split a line, or change terminal state.
    const covered: number[] = [];
    for (let c = 0x00; c <= 0x9f; c++) {
      if (c >= 0x20 && c <= 0x7e) continue; // printable ASCII
      covered.push(c);
    }
    covered.push(0x2028, 0x2029);

    for (const code of covered) {
      const label = `U+${code.toString(16).padStart(4, '0')}`;
      const out = escapeForDisplay(`before${String.fromCodePoint(code)}after`);
      expect(out, `${label} survived escaping`).not.toContain(String.fromCodePoint(code));
      expect(out.split('\n'), `${label} split the line`).toHaveLength(1);
      expect(out.startsWith('before'), `${label} corrupted the text before it`).toBe(true);
      expect(out.endsWith('after'), `${label} corrupted the text after it`).toBe(true);
    }

    // Non-vacuity: the loop must have actually covered the interesting bytes.
    expect(covered).toContain(0x0a);
    expect(covered).toContain(0x1b);
    expect(covered.length).toBeGreaterThan(60);
  });

  it('leaves printable characters outside ASCII alone', () => {
    // Escaping must not mangle a legitimate non-English path.
    const path = "rm -rf '/Users/me/projets/données/配置'";
    expect(escapeForDisplay(path)).toBe(path);
  });

  /**
   * #334 — two different files must not render as the same text.
   *
   * `escapeForDisplay` is not injective: a directory literally named `dir\nx`
   * (five characters) renders exactly like one named `dir<LF>x`. For a module
   * whose stated purpose is keeping the rendered text a faithful description of
   * what was found, that is the defect rather than a detail.
   *
   * The doubling lives in a separate function because it is only correct on a
   * bare path: `escapeForDisplay` is also applied to composed lines, where a
   * backslash may already be shell syntax or an escape this module produced, and
   * doubling there would corrupt the command and would not be idempotent.
   */
  it('escapePathForDisplay distinguishes a real control character from a literal escape', () => {
    const realLF = 'dir\nx';
    const literal = 'dir\\nx';

    expect(escapeForDisplay(realLF), 'the shared escaper is expected to collapse these')
      .toBe(escapeForDisplay(literal));
    expect(
      escapePathForDisplay(realLF),
      'two different paths still render identically',
    ).not.toBe(escapePathForDisplay(literal));
    expect(escapePathForDisplay(realLF)).toBe('dir\\nx');
    expect(escapePathForDisplay(literal)).toBe('dir\\\\nx');
  });

  it('escapePathForDisplay still neutralizes everything the shared escaper does', () => {
    const ESC_CH = String.fromCodePoint(0x1b);
    const out = escapePathForDisplay(`a${ESC_CH}[2Jb\nc${String.fromCodePoint(0x202e)}d`);
    expect(out).not.toContain(ESC_CH);
    expect(out.split('\n')).toHaveLength(1);
    expect(out).toContain('\\u202e');
  });

  /**
   * #330 — the class that makes a DISPLAYED path differ from the real one.
   *
   * These are not cosmetic: `U+202E` + `gnp.elif_ngineb` renders as
   * `benign_file.png`, so a destructive command's argument reads as one
   * directory and names another. Measured before the fix: all 17 of these passed
   * through `escapeForDisplay` unchanged.
   */
  it('escapes bidi, zero-width and format controls', () => {
    const covered = [
      0x00ad, 0x061c,
      0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
      0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
      0x2066, 0x2067, 0x2068, 0x2069,
      0xfeff,
    ];

    for (const code of covered) {
      const label = `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
      const ch = String.fromCodePoint(code);
      const out = escapeForDisplay(`before${ch}after`);
      expect(out, `${label} reached the terminal unescaped`).not.toContain(ch);
      expect(out.startsWith('before'), `${label} corrupted the text before it`).toBe(true);
      expect(out.endsWith('after'), `${label} corrupted the text after it`).toBe(true);
    }

    // The measured spoof: what is displayed must not read as a different name.
    const spoof = `.${String.fromCodePoint(0x202e)}gnp.elif_ngineb`;
    expect(escapeForDisplay(spoof)).toBe('.\\u202egnp.elif_ngineb');
  });

  /**
   * #959 — the unassigned plane-14 runs U+E0000, U+E0002-U+E001F,
   * U+E0080-U+E00FF and U+E01F0-U+E01FF are `\p{Cn}`, so neither `\p{Cf}` nor
   * the variation-selector class matched them, while the steganography checks
   * report them. Measured before the fix: `benign` + U+E01F0 + `evil.js` came
   * back unchanged; the first fix named only the last two runs, and
   * U+E0000 and U+E0002 still came back unchanged.
   */
  it('escapes the unassigned plane-14 code points the steganography checks report', () => {
    const covered = [0xe0000, 0xe0002, 0xe001f, 0xe0080, 0xe00ff, 0xe01f0, 0xe01ff];
    const pictograph = String.fromCodePoint(0x2764);

    for (const code of covered) {
      const label = `U+${code.toString(16).toUpperCase()}`;
      const ch = String.fromCodePoint(code);
      expect(escapeForDisplay(`benign${ch}evil.js`), label).toBe(`benign\\u{${code.toString(16)}}evil.js`);
      // Not a variation selector, so a preceding pictograph does not exempt it.
      expect(escapeForDisplay(`${pictograph}${ch}`), `${label} after a pictograph`).toBe(`${pictograph}\\u{${code.toString(16)}}`);
    }

    // The assigned neighbours are still escaped: the end of the Tags block and
    // the last supplementary variation selector.
    expect(escapeForDisplay(String.fromCodePoint(0xe007f))).toBe('\\u{e007f}');
    expect(escapeForDisplay(`a${String.fromCodePoint(0xe01ef)}`)).toBe('a\\u{e01ef}');
  });

  it('escapes every code point in U+E0000-U+E01FF after a plain letter (the range the checks report)', () => {
    const unescaped: string[] = [];
    for (let code = 0xe0000; code <= 0xe01ff; code++) {
      const out = escapeForDisplay(`a${String.fromCodePoint(code)}b`);
      if (out !== `a\\u{${code.toString(16)}}b`) unescaped.push(`U+${code.toString(16).toUpperCase()}`);
    }
    expect(unescaped).toEqual([]);
  });

  /**
   * #999 — U+E0200-U+EFFFF is unassigned and renders as nothing, like the
   * runs #959 named. Measured before the fix: `a` + U+E0200 + `b` came back
   * unchanged.
   */
  it('escapes every plane-14 code point, including the unassigned ones above U+E01FF', () => {
    expect(escapeForDisplay(`a${String.fromCodePoint(0xe0200)}b`)).toBe('a\\u{e0200}b');
    const unescaped: string[] = [];
    for (let code = 0xe0000; code <= 0xeffff; code++) {
      const out = escapeForDisplay(`a${String.fromCodePoint(code)}b`);
      if (out !== `a\\u{${code.toString(16)}}b`) unescaped.push(`U+${code.toString(16).toUpperCase()}`);
    }
    expect(unescaped.slice(0, 5), `${unescaped.length} plane-14 code points printed raw`).toEqual([]);
  });

  /**
   * #999 — the pictograph exemption covered every variation selector, but only
   * U+FE0E and U+FE0F choose a pictograph's presentation. Measured before the
   * fix: `❤` + U+E0100 + `evil.js`, a path UNICODE-STEGO-001 reports, came
   * back unchanged, and so did `🚀` + U+FE01, the head of a hidden selector run.
   */
  it('exempts only U+FE0E and U+FE0F after a pictograph', () => {
    const heart = String.fromCodePoint(0x2764);
    const rocket = String.fromCodePoint(0x1f680);
    expect(escapeForDisplay(`${heart}${String.fromCodePoint(0xe0100)}evil.js`)).toBe(`${heart}\\u{e0100}evil.js`);
    expect(escapeForDisplay(`${rocket}${String.fromCodePoint(0xfe01)}`)).toBe(`${rocket}\\ufe01`);

    const raw: string[] = [];
    const selectors = [
      ...Array.from({ length: 14 }, (_, i) => 0xfe00 + i),
      ...Array.from({ length: 0xe01ef - 0xe0100 + 1 }, (_, i) => 0xe0100 + i),
    ];
    for (const code of selectors) {
      const ch = String.fromCodePoint(code);
      if (escapeForDisplay(`${heart}${ch}`).includes(ch)) raw.push(`U+${code.toString(16).toUpperCase()}`);
    }
    expect(raw).toEqual([]);

    // The two presentation selectors keep their exemption after a pictograph
    // and are escaped after anything else.
    for (const code of [0xfe0e, 0xfe0f]) {
      const ch = String.fromCodePoint(code);
      expect(escapeForDisplay(`${heart}${ch}.txt`)).toBe(`${heart}${ch}.txt`);
      expect(escapeForDisplay(`a${ch}b`)).toBe(`a\\u${code.toString(16)}b`);
    }
  });
});
