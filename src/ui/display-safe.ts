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
 * The class is: SOFT HYPHEN, ARABIC LETTER MARK, the zero-width and directional
 * marks (U+200B..U+200F), the bidi embeddings and overrides (U+202A..U+202E),
 * the bidi isolates (U+2066..U+2069) and the BOM/ZWNBSP (U+FEFF). Escaped
 * visibly rather than stripped, per the rule below: dropping is what truncated
 * the command in #324.
 */
const CONTROL_CHARS = new RegExp(
  '[\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u200b-\\u200f'
  + '\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069\\ufeff]',
  'g',
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
 * Make control characters visible so a single-line render stays a single line.
 *
 * Total: every replaced character maps to printable ASCII, so the result cannot
 * split a line, move the cursor, or change the terminal's state. Text with no
 * control characters is returned unchanged, which is the overwhelmingly common
 * case and keeps every existing rendering byte-identical.
 */
export function escapeForDisplay(text: string): string {
  return text.replace(CONTROL_CHARS, (ch) => {
    const code = ch.codePointAt(0) ?? 0;
    const named = NAMED[code];
    if (named) return named;
    return code > 0xff
      ? `\\u${code.toString(16).padStart(4, '0')}`
      : `\\x${code.toString(16).padStart(2, '0')}`;
  });
}

/**
 * The same escaping for a BARE path, and injective (#334).
 *
 * `escapeForDisplay` is not one-to-one: a directory literally named `dir\nx` —
 * five characters, backslash then `n` — renders exactly like one named `dir<LF>x`.
 * For a module whose stated purpose is keeping "the rendered text a faithful
 * description of what was found", two different files reading identically is the
 * defect, not a detail. Escaping the escape character first fixes it.
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
export function escapePathForDisplay(p: string): string {
  return escapeForDisplay(p.split('\\').join('\\\\'));
}
