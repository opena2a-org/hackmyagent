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
import { escapePathForDisplay } from './display-safe';

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
 *
 * #340 — `~` used to be on this list, and tilde expansion is exactly the thing
 * this function exists to prevent: `<project>/~/evil.txt` was displayed and
 * `rm ~/evil.txt` was emitted, so pasting it acted on `$HOME`. A file named `~`
 * alone yielded `rm ~`.
 */
const SAFE_UNQUOTED = /^[A-Za-z0-9._@:+=/-]+$/;

/**
 * A path as it should appear inside a command citation a human will read and
 * paste, or null when no correct command can name it.
 *
 * **The rule: a line never shows one path two ways.** The citation is emitted
 * only when the path is displayed exactly as it is — `escapePathForDisplay`
 * leaves it unchanged. Otherwise what the reader sees is a RENDERING, and any
 * command built from the real bytes names something the reader cannot see.
 *
 * #343 — the previous version escaped for display AFTER quoting, so the escape
 * landed between the quotes. For a file named `nl<LF>second` it emitted
 * `rm 'nl\nsecond'`, which in any POSIX shell names a ten-character file with a
 * literal backslash — not the one the report is about. An attacker who creates
 * both names gets the user to delete the wrong one; otherwise the citation is a
 * dead end that fails with "no such file". `generateVerifyCommand` already took
 * the other route for its own case, omitting a command it cannot render rather
 * than emitting a wrong one, and this is the same rule.
 *
 * #347.5 — and it is also what stops one path being rendered two ways in one
 * line, which the previous version did for any path containing a backslash.
 *
 * #340 — a leading `-` is an argument, not a path, to every command that takes
 * flags: a file named `-rf` rendered `rm -rf`, and `-i` or `--no-preserve-root`
 * rendered themselves. Prefixing `./` makes it an operand again, and reads the
 * same to a human. Quoting alone does not help — the shell strips the quotes
 * before the command sees the word.
 *
 * Quoting only when necessary is deliberate. Citations are the most-read output
 * this tool produces, and `secure './proj'` reads like an incantation where
 * `secure ./proj` reads like a command — while the byte-compared corpus goldens,
 * whose targets are all ordinary paths, stay unchanged.
 *
 * Human-readable output only. A `--json` consumer needs the real bytes.
 */
export function citationPath(p: string): string | null {
  if (escapePathForDisplay(p) !== p) return null;
  const operand = p.startsWith('-') ? `./${p}` : p;
  return SAFE_UNQUOTED.test(operand) ? operand : shellQuote(operand);
}

/**
 * The scan TARGET as it should appear in a citation, falling back to the house
 * `<dir>` placeholder.
 *
 * For a target the reader cannot be shown truthfully, `<dir>` is already this
 * project's answer (it is what a remote target gets): the citation stays
 * runnable once the reader fills it in, which is a path forward, where a command
 * naming bytes the reader cannot see is a command that acts on the wrong file.
 *
 * Only for a target spliced into a command that must remain runnable. A citation
 * whose subject is already named on the same line — the rollback report's `rm` —
 * should take the null and omit the command instead.
 */
export function citationTarget(p: string): string {
  return citationPath(p) ?? '<dir>';
}
