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
import { hasDisplayHazard } from './display-safe';

/**
 * POSIX only, deliberately (#347.7).
 *
 * The question was raised as a defect: `escapePathForDisplay` doubles every
 * backslash so a Windows path renders `C:\\proj\\src`, and `SAFE_UNQUOTED`
 * excludes `\`, so every Windows path in a citation is POSIX-single-quoted —
 * wrong in `cmd.exe`. The answer to "is Windows supported" has to come first,
 * and it is NO: `src/` contains zero `process.platform`/`win32` branches, the
 * README makes no Windows claim, `package.json` declares no `os`, and every CI
 * job runs `ubuntu-latest`. Nothing here has ever run on Windows.
 *
 * So the quoting stays POSIX. Adding a `cmd.exe` branch would add an untested
 * code path for a platform with no CI, on the function whose whole job is that
 * the emitted command names the file it displays. Declaring `"os"` in
 * package.json so `npm i` refuses on Windows is the honest next step, and it is
 * a product decision rather than a review fix — tracked separately.
 */

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
 *
 * And `=` was still on it after that. zsh expands a leading `=` to the resolved
 * path of a command — EQUALS expansion, on by default, and zsh is the default
 * shell on macOS — so a file named `=python3` rendered `rm =python3`, which in
 * the shell the reader is actually typing into means
 * `rm /opt/homebrew/bin/python3`. Measured: `sh -c "printf '%s\n' =python3"`
 * prints `=python3`, `zsh -c` prints `/opt/homebrew/bin/python3`. The list is
 * now only characters no common shell expands anywhere in a word.
 */
const SAFE_UNQUOTED = /^[A-Za-z0-9._@:+/-]+$/;

/**
 * A path as it should appear inside a command citation a human will read and
 * paste, or null when no correct command can name it.
 *
 * **The rule: a path the reader cannot be shown truthfully gets no command.**
 * The citation is emitted unless the path carries a character the terminal would
 * act on or hide — a control byte, a bidi override, an invisible format
 * character. Those are displayed as a RENDERING, so any command built from the
 * real bytes names something the reader cannot see.
 *
 * The first version of this rule was `escapePathForDisplay(p) !== p`, which is a
 * stricter and WRONG predicate: for `a\test.json` the only difference is this
 * module's own backslash doubling, and `rm 'a\test.json'` is a perfectly correct
 * command. That version printed "its name carries characters a pasted command
 * cannot name" about a path a command names fine — a dead end plus a false
 * statement, where the previous build got it right. A backslash followed by one
 * of this module's escape letters therefore still renders differently from its
 * citation; that difference is forced (the display must distinguish `a\test` from
 * `a<TAB>est`) and is the honest residual of #347.5 rather than a reason to
 * withhold a working command.
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
  if (hasDisplayHazard(p)) return null;
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
