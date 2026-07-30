/**
 * POSIX single-quoting for a path that goes into a citation the user will paste.
 *
 * A bare `'…'` wrapper is not enough: a directory whose name contains an
 * apostrophe closes the quote early, and the remainder of the path is then
 * re-parsed by the shell. The standard construction — end the quote, add an
 * escaped literal quote, start a new one — is total, because nothing inside a
 * single-quoted POSIX string is special otherwise.
 *
 * #328 — this lives here, on its own, because it had been written twice inside
 * the scanner under two names and was still missing from the report that emits
 * the most dangerous citation. `rollback` built `rm ${file}` by concatenation
 * from a manifest path, which is a file in the scanned tree, so pasting the
 * citation HackMyAgent printed ran `touch PWNED-BY-CITATION`:
 *
 *   kept   pwn.txt'; touch PWNED-BY-CITATION; echo '  — review, then
 *          `rm pwn.txt'; touch PWNED-BY-CITATION; echo '` if unwanted
 *
 * A path is data. Any command a report tells the user to run has to quote it,
 * whichever report is doing the telling — see
 * `__tests__/helpers/render-safety.ts`, where that property is stated once and
 * run over every command that renders a path.
 *
 * Quoting is not display escaping: it makes the command CORRECT, not readable.
 * A path carrying a control character still needs `escapeForDisplay` around the
 * rendered line, and the two compose in that order — quote the path, then escape
 * the line that carries it.
 */
import { escapeForDisplay } from './display-safe';

/**
 * POSIX single-quote a string. Total: nothing inside a single-quoted string is
 * special, and an embedded quote is closed, escaped and reopened.
 */
export function shellQuote(p: string): string {
  return `'${p.split("'").join(`'\\''`)}'`;
}

/**
 * Characters a path may contain and still be pasted unquoted. Everything else —
 * spaces, quotes, `;`, `&`, `$`, backticks, newlines, control bytes — either
 * changes what the shell does or what the terminal shows.
 */
const SAFE_UNQUOTED = /^[A-Za-z0-9._@:+=/~-]+$/;

/**
 * A path as it should appear inside a command citation a human will read and
 * paste: quoted when it needs quoting, then escaped for display.
 *
 * Quoting only when necessary is deliberate. Citations are the most-read output
 * this tool produces, and `secure './proj'` reads like an incantation where
 * `secure ./proj` reads like a command — while the byte-compared corpus goldens,
 * whose targets are all ordinary paths, stay unchanged. A path that needs
 * quoting gets it, and one that needs display escaping gets that too, in the
 * order that composes: the quoting decides what the shell will do, the escaping
 * decides what the terminal will show.
 *
 * Human-readable output only. A `--json` consumer needs the real bytes, and
 * `escapeForDisplay` is a display transformation — see its own docstring.
 */
export function citationPath(p: string): string {
  return escapeForDisplay(SAFE_UNQUOTED.test(p) ? p : shellQuote(p));
}
