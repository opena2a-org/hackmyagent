/**
 * Rendering a path that came out of the scanned tree (#324).
 *
 * Every path in a finding is attacker-influenced data: it is a filename from the
 * directory being audited. Two things go wrong when such a path is written
 * straight to a terminal line.
 *
 * A newline SPLITS the line. Measured on a directory named
 * `2026-01-01-000000<LF>EVIL-SECOND-LINE`:
 *
 *     Fix: rm -rf '/…/.hackmyagent-backup/2026-01-01-000000
 *
 * The command HMA emitted was correct and safe — `shellQuote` is total, and
 * executing the emitted argument removed the right directory and fired no
 * substitution. What broke was the display: the renderer keeps only the first
 * non-blank line, so the visible command ends mid-quote and pasting what is on
 * screen leaves the shell at a `quote>` continuation prompt.
 *
 * An ESC byte is worse than cosmetic: `ESC [ 2 J` would clear the user's
 * terminal from inside a security report, and a CSI sequence can overwrite the
 * lines above it — which means a path could edit the report describing it.
 *
 * So control characters are made VISIBLE rather than dropped. Dropping is what
 * produced the truncated command; escaping keeps the whole path on one line and
 * keeps the rendered text a faithful description of what was found.
 *
 * `generateVerifyCommand` takes the other correct route for its own case: a path
 * with control characters yields no Verify line at all, because a copy-pasteable
 * command that cannot be safely rendered is better omitted than shown wrong. A
 * `Fix:` line cannot be omitted the same way — that would leave the finding with
 * no path forward, which is the dead end this project's rules forbid.
 */

/**
 * C0, DEL, C1, the two Unicode line separators, and the bidi/format controls.
 *
 * Built from a string of `\u` escapes rather than written as a regex literal: a
 * literal control byte inside a character class is invisible in every diff and
 * every editor that would review it, and this is a security-relevant pattern.
 *
 * #330 — the bidi and zero-width classes were missing, and they are the ones
 * that make a DISPLAYED path differ from the real one. A directory named
 * U+202E followed by `gnp.elif_ngineb` renders as `benign_file.png`; the
 * `Fix:` line naming it then describes a directory that is not the one the
 * command acts on. That is the same harm this module already fixes for CSI
 * sequences — "a path could edit the report describing it" — and it landed on
 * the one citation that was destructive.
 *
 * It named seventeen code points one at a time: SOFT HYPHEN, ARABIC LETTER MARK,
 * the zero-width and directional marks, the bidi embeddings, overrides and
 * isolates, and the BOM. Escaped visibly rather than stripped, per the rule
 * below: dropping is what truncated the command in #324.
 *
 * #345 — and an enumerated list is the wrong shape for this class. That list
 * grew one reporter at a time and still missed the families the scanner itself
 * hunts: the Unicode TAG block (U+E0000..U+E007F, which HackMyAgent's own
 * steganography check reports as an ATTACK, emitting `xxd … | grep "f3a0"` for
 * its UTF-8 prefix), the variation selectors, the word joiner and the invisible
 * operators, the Hangul fillers, the Mongolian vowel separator and the musical
 * format controls. One module called those bytes an attack while another printed
 * them silently, and `benign<U+E0041…>evil.png` renders with nothing visible
 * between the parts — #330's harm statement verbatim.
 *
 * So the class is a CATEGORY, and it cannot fall behind a reporter again:
 * `\p{Cc}` (C0, DEL, C1), `\p{Cf}` (every format character, including the tag
 * block, the bidi marks, the joiners and the Arabic number signs), `\p{Zl}` and
 * `\p{Zp}` (the two Unicode line separators), plus the two families that are
 * invisible without being Cc/Cf: the variation selectors, and the Hangul filler
 * letters that render as nothing.
 *
 * One deliberate exemption: a variation selector that FOLLOWS a pictograph is
 * emoji presentation, not concealment — the character it modifies is visible and
 * is what the reader sees. Escaping those would turn every `❤️` in a filename
 * into `❤️` for no gain. A variation selector after anything else has
 * nothing visible to modify, and is escaped.
 */
const DISPLAY_HAZARD = new RegExp(
  '[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}\\u{115F}\\u{1160}\\u{3164}\\u{FFA0}]'
  + '|(?<!\\p{Extended_Pictographic})[\\u{FE00}-\\u{FE0F}\\u{E0100}-\\u{E01EF}]',
  'gu',
);

/** Keyed by code point, for the same reason: no control characters in source. */
const NAMED: Record<number, string> = {
  0x00: '\\0',
  0x09: '\\t',
  0x0a: '\\n',
  0x0d: '\\r',
  0x1b: '\\e',
};

/**
 * One code point, rendered visibly. Astral code points take `\u{…}` braces:
 * `1` is five hex digits where `\uXXXX` is four, so U+E0041 and
 * U+E004 followed by `1` produced the same text — an injectivity hole in the
 * escape alphabet itself.
 */
function escapeCodePoint(code: number): string {
  const named = NAMED[code];
  if (named) return named;
  if (code <= 0xff) return `\\x${code.toString(16).padStart(2, '0')}`;
  return code <= 0xffff
    ? `\\u${code.toString(16).padStart(4, '0')}`
    : `\\u{${code.toString(16)}}`;
}

/**
 * Make invisible and terminal-controlling characters visible, so a single-line
 * render stays a single line and says what is really there.
 *
 * Total: every replaced character maps to printable ASCII, so the result cannot
 * split a line, move the cursor, or change the terminal's state. Text with no
 * such characters is returned unchanged, which is the overwhelmingly common case
 * and keeps every existing rendering byte-identical.
 */
export function escapeForDisplay(text: string): string {
  return text.replace(DISPLAY_HAZARD, (ch) => escapeCodePoint(ch.codePointAt(0) ?? 0));
}

/** True when `escapeForDisplay` would change `text` — i.e. what is shown is a rendering. */
export function hasDisplayHazard(text: string): boolean {
  DISPLAY_HAZARD.lastIndex = 0;
  return DISPLAY_HAZARD.test(text);
}

/**
 * The same escaping for a BARE path, and injective (#334).
 *
 * `escapeForDisplay` is not one-to-one: a directory literally named `dir\nx` —
 * five characters, backslash then `n` — renders exactly like one named `dir<LF>x`.
 * For a module whose stated purpose is keeping "the rendered text a faithful
 * description of what was found", two different files reading identically is the
 * defect, not a detail. Escaping the escape character fixes it.
 *
 * #347.5 — but escaping EVERY backslash bought that at the cost of a second
 * defect: one path rendered two ways in one line. `a\b.txt` displayed as
 * `a\\b.txt` beside a citation reading `rm 'a\b.txt'`, and a reader has no way
 * to tell which of the two is the file. A backslash only needs escaping when it
 * could be READ as one of this module's own escapes, so only those are doubled:
 * a backslash followed by `0`, `t`, `n`, `r`, `e`, `x`, `u`, another backslash,
 * or a character that is about to BECOME an escape. `a\b.txt` renders as itself
 * and matches its citation; `dir\nx` still renders `dir\\nx`, distinct from
 * `dir<LF>x`.
 *
 * It is a SEPARATE function because doubling backslashes is only correct on a
 * raw path. `escapeForDisplay` is also applied to composed text — fix lines,
 * guidance, citations — where a backslash may already be shell syntax
 * (`'…'\''…'` is how a quoted path carries an apostrophe) or an escape this
 * module itself produced. Doubling there would change a correct command into a
 * wrong one, and would not be idempotent: `\n` would grow on every pass.
 *
 * So: this one for a path rendered on its own, `escapeForDisplay` for a line
 * built out of one.
 */
const AMBIGUOUS_AFTER_BACKSLASH = new Set(['0', 't', 'n', 'r', 'e', 'x', 'u', '\\']);

export function escapePathForDisplay(p: string): string {
  // TWO passes, and the order matters. Doubling is decided per character with a
  // one-character lookahead; escaping is decided over the WHOLE string, because
  // the pictograph exemption is a lookbehind and a per-character test cannot see
  // what precedes it. Doing both in one loop escaped every variation selector,
  // so `❤️.txt` rendered `❤\ufe0f.txt` and lost its citation — the exact outcome
  // the exemption exists to prevent, in the one function that renders a bare
  // filename.
  const chars = [...p];
  let doubled = '';
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (ch !== '\\') {
      doubled += ch;
      continue;
    }
    const next = chars[i + 1];
    // A trailing backslash cannot be read as an escape: there is nothing after
    // it to complete one. A backslash before a hazard is ambiguous whatever the
    // exemption says, because the backslash itself now stands between the
    // pictograph and the selector.
    const ambiguous = next !== undefined
      && (AMBIGUOUS_AFTER_BACKSLASH.has(next) || hasDisplayHazard(next));
    doubled += ambiguous ? '\\\\' : '\\';
  }
  return escapeForDisplay(doubled);
}
