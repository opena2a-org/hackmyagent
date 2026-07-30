/**
 * The rendering property, stated once (#328).
 *
 * Every path in a report is attacker-influenced data: it is a filename from the
 * directory being audited. Two things must hold of every command HackMyAgent
 * renders, on every code path that renders one:
 *
 *   1. No raw control byte from the scanned tree reaches the terminal. A newline
 *      splits the line — so a command ends mid-quote and pasting what is on
 *      screen leaves the shell at a continuation prompt — and an `ESC [ 2 J`
 *      clears the user's terminal from inside a security report.
 *   2. Every path inside a command the report tells the user to RUN is
 *      shell-quoted. Otherwise a filename is a command: `pwn.txt'; touch
 *      PWNED-BY-CITATION; echo '` produced `rm pwn.txt'; touch
 *      PWNED-BY-CITATION; echo '`, and the user was told to paste it.
 *
 * #324 fixed ten render sites in `secure` and wrote the assertion for `secure`
 * alone. `rollback`'s four "kept" lines were built by string concatenation from
 * a manifest path, with neither escaping nor quoting, and that is the report
 * that emits an `rm`. A property asserted about one command is not a property.
 *
 * Everything here is written as `\x`/`\u` escapes or `String.fromCodePoint`: a
 * literal control byte in test source is invisible in every diff that would
 * review it.
 */
import { expect } from 'vitest';

/**
 * One basename carrying every hazard at once: a quote that closes a shell
 * string, a command separator, a newline that splits a rendered line, and a CSI
 * sequence that rewrites the terminal.
 */
export const HOSTILE_NAME = [
  "pwn.txt'; touch PWNED-BY-CITATION; echo '",
  '\nEVIL-SECOND-LINE',
  `${String.fromCodePoint(0x1b)}[2Jcleared`,
].join('');

/** The marker that must never start a line of its own. */
export const SPLIT_MARKER = 'EVIL-SECOND-LINE';

/**
 * Property 1 — no raw control byte from the scanned tree.
 *
 * The tool's own layout uses newline and tab, so those two cannot be judged
 * here; property 2 covers an injected newline by asserting no line splits.
 * Everything else below 0x20, plus DEL, could only have come from a path.
 */
export function assertNoRawControlBytes(out: string, label: string): void {
  const offenders = [...out].filter((ch) => {
    const c = ch.codePointAt(0) ?? 0;
    return (c < 0x20 && c !== 0x0a && c !== 0x09) || c === 0x7f;
  });
  expect(
    offenders.length,
    `${label}: a raw control character from the scanned tree reached the terminal`,
  ).toBe(0);
}

/** Property 1b — an injected newline did not split a rendered line. */
export function assertNoSplitLines(out: string, label: string): void {
  for (const line of out.split('\n')) {
    expect(
      line.startsWith(SPLIT_MARKER),
      `${label}: the path's newline became a line break: ${JSON.stringify(line)}`,
    ).toBe(false);
  }
}

/**
 * Property 2 — every `rm` citation quotes its argument.
 *
 * Deliberately checks the SHAPE rather than one expected string: any renderer
 * that emits `rm <path>` has to quote, whichever path and whichever report. The
 * argument's first character after the flags must be a single quote.
 */
export function assertCitationsQuoted(out: string, label: string): void {
  for (const line of out.split('\n')) {
    for (const m of line.matchAll(/\brm(?:\s+-[A-Za-z]+)*\s+(\S)/g)) {
      expect(
        m[1],
        `${label}: an rm citation names an unquoted path, so a filename is a `
        + `command: ${JSON.stringify(line)}`,
      ).toBe("'");
    }
  }
}

/** All of it, for one command's output. */
export function assertRenderSafe(out: string, label: string): void {
  assertNoRawControlBytes(out, label);
  assertNoSplitLines(out, label);
  assertCitationsQuoted(out, label);
}
