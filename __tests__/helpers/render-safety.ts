/**
 * The rendering property, stated once (#328), over every command (#339), and
 * stated independently of the implementation (#340).
 *
 * Every path in a report is attacker-influenced data: it is a filename from the
 * directory being audited. Three things must hold of every command HackMyAgent
 * renders, on every code path that renders one:
 *
 *   1. No raw control byte from the scanned tree reaches the terminal. A newline
 *      splits the line — so a command ends mid-quote and pasting what is on
 *      screen leaves the shell at a continuation prompt — and an `ESC [ 2 J`
 *      clears the user's terminal from inside a security report.
 *   2. Every path inside a command the report tells the user to RUN resolves,
 *      through a real shell, back to exactly the file the report is about.
 *   3. That path is an OPERAND, not something a command could read as a flag.
 *
 * #324 fixed ten render sites in `secure` and wrote the assertion for `secure`
 * alone. #328 then fixed `rollback` and `check` and wrote the assertion for
 * four commands — and `detect`, `scan-soul`, `harden-soul` and `wild` were still
 * emitting raw attacker paths, six injectable citations in `detect` alone. So
 * the LIST lives here now, beside the property, and `render-command-coverage`
 * fails when a command is registered without being classified against it.
 *
 * #340 — and property 2 used to be a copy of the implementation's own allowlist.
 * `SHELL_INERT` restated `SAFE_UNQUOTED` from `src/ui/shell-quote.ts`, so it
 * agreed with the hole it was written to catch and passed `rm ~/evil.txt`, which
 * deletes `$HOME/evil.txt` while the report displays a project path. A test that
 * copies the implementation is not an independent statement of anything: this
 * one asks `sh` what the emitted command actually names.
 *
 * Everything here is written as `\x`/`\u` escapes or `String.fromCodePoint`: a
 * literal control byte in test source is invisible in every diff that would
 * review it.
 */
import { execFileSync } from 'node:child_process';
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
 * Shell-hostile, display-CLEAN: a quote that closes a shell string and a command
 * separator, and nothing a terminal would act on.
 *
 * `HOSTILE_NAME` cannot exercise the quoting property any more. Since #343 a
 * path carrying a control character gets no command at all — the report cannot
 * show it truthfully AND name it correctly, so it names it once and says to act
 * by hand. That is the right behaviour and it makes the citation half vacuous on
 * that fixture. This name is the one that must come back QUOTED.
 */
export const SHELL_HOSTILE_NAME = "pwn.txt'; touch PWNED-BY-CITATION; echo 'x";

/**
 * Every command registered in `src/cli.ts`, classified.
 *
 * `renders-paths` commands must run the property. The rest carry the reason they
 * do not, so the classification is a decision on the record rather than an
 * omission. `render-command-coverage.test.ts` reads the `.command('…')` calls
 * out of the source and fails when a name here is stale or a new one is
 * unclassified — which is what makes "we forgot to add it" the failing case.
 */
export const COMMAND_CLASSIFICATION: Record<string, 'renders-paths' | string> = {
  secure: 'renders-paths',
  // Was: "scans an external network endpoint; its target is a host the user
  // typed, not a path from a scanned tree." It also catches `scan ./project`
  // and renders that path back in the hint that points at `secure`.
  scan: 'renders-paths',
  check: 'renders-paths',
  detect: 'renders-paths',
  'scan-soul': 'renders-paths',
  'harden-soul': 'renders-paths',
  wild: 'renders-paths',
  rollback: 'renders-paths',
  'fix-all': 'renders-paths',
  'secure-openclaw': 'renders-paths',
  'secure-nemoclaw': 'renders-paths',
  // The four the classification got WRONG, and the reason each was wrong:
  //   create-skill  prints the output directory and every file it wrote
  //   init-mcp      prints the config path it created or found — and that one
  //                 is relative and comes from a three-entry table, so it is
  //                 the weakest of the four: the escape is insurance, not a
  //                 measured hazard. Classified here so it stays covered.
  //   attack        prints `--payload-file` on the error channel, and a
  //                 `--target-type local` directory in its header
  //   red-team      prints its target four times when the artifact is missing
  // "Arguments the user typed" was doing the work in three of these, and it is
  // not a reason: a path the user typed still renders, and a report that splits
  // its own line is the same defect whoever supplied the bytes.
  'create-skill': 'renders-paths',
  'init-mcp': 'renders-paths',
  attack: 'renders-paths',
  'red-team': 'renders-paths',
  eval: 'renders benchmark identifiers and scores, not filesystem paths',
  explain: 'renders a check ID and static prose',
  'check-metadata': 'renders the tool\'s own catalogue',
  trust: 'renders registry data for a package name',
  telemetry: 'renders the local telemetry state',
  status: 'renders the tool\'s own state',
  setup: 'interactive configuration of the tool itself',
  nanomind: 'renders model identifiers and local model state',
  'mcp-serve': 'a server, not a report',
  'pull-stubs': 'downloads model stubs; renders the tool\'s own cache paths',
  'mark-stub': 'renders a stub id, a status word and the PATCH body it would send; no filesystem path reaches its output',
};

/**
 * Property 1 — no raw control byte from the scanned tree.
 *
 * The tool's own layout uses newline and tab, so those two cannot be judged
 * here; property 1b covers an injected newline by asserting no line splits.
 * Everything else below 0x20, plus DEL, could only have come from a path.
 */
export function assertNoRawControlBytes(out: string, label: string): void {
  const offenders = locateRawControlBytes(out);
  expect(
    offenders.length,
    `${label}: a raw control character from the scanned tree reached the terminal`
    + `\n${describeOffenders(out, offenders)}`,
  ).toBe(0);
}

/** Every offending codepoint, with its offset, in order. */
export function locateRawControlBytes(out: string): Array<{ index: number; code: number }> {
  const found: Array<{ index: number; code: number }> = [];
  for (let i = 0; i < out.length; i += 1) {
    const c = out.codePointAt(i) ?? 0;
    if ((c < 0x20 && c !== 0x0a && c !== 0x09) || c === 0x7f) found.push({ index: i, code: c });
  }
  return found;
}

/**
 * Say WHICH byte and WHERE, because `expected 2 to be +0` is a dead end.
 *
 * This assertion failed six times on `ubuntu-latest` and the message gave a
 * count and nothing else — no codepoint, no offset, no surrounding text — so
 * the only way to learn anything was to push a branch and add this. The
 * offender is not always HackMyAgent's: a native dependency that logs in
 * colour writes ESC to the same stderr, and a count cannot tell the two apart.
 *
 * The context window is escaped, so nothing here re-emits the very control
 * byte the assertion exists to keep off a terminal.
 *
 * `JSON.stringify` ALONE is not that escape, which is worth stating because
 * the first version of this claimed it was. It escapes C0 — everything below
 * 0x20 — and stops: DEL (0x7f) passes through raw, and DEL is one of the 31
 * codepoints this very assertion flags. So a filename carrying a DEL would
 * have made the diagnostic print the byte it was reporting. C1 (0x80–0x9f)
 * passes through raw too, and 0x9b is a single-byte CSI that a terminal acts
 * on exactly like `ESC [`. Both ranges are escaped here explicitly.
 */
function describeOffenders(
  out: string,
  offenders: ReadonlyArray<{ index: number; code: number }>,
  limit = 5,
): string {
  if (offenders.length === 0) return '';
  const lines = offenders.slice(0, limit).map(({ index, code }) => {
    const hex = `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
    const context = escapeForMessage(out.slice(Math.max(0, index - 60), index + 60));
    return `  ${hex} at offset ${index}, in: ${context}`;
  });
  if (offenders.length > limit) lines.push(`  …and ${offenders.length - limit} more`);
  return lines.join('\n');
}

/**
 * A quoted rendering of a fragment with no byte a terminal acts on.
 *
 * `JSON.stringify` first, so quotes and backslashes are handled and C0 becomes
 * `\uXXXX`; then DEL and C1, which it leaves raw, escaped the same way. The
 * order matters — escaping first would leave the introduced backslashes to be
 * doubled by `stringify`, and the message would read `\\u001b`.
 */
/** DEL. `JSON.stringify` escapes C0 and stops exactly one byte short of it. */
const DEL = 0x7f;
/** End of C1. 0x9b inside this range is a single-byte CSI, i.e. `ESC [`. */
const C1_END = 0x9f;

export function escapeForMessage(fragment: string): string {
  // Compared NUMERICALLY rather than matched by a character class. Per this
  // file's header a literal control byte in source is invisible in the diff
  // that would review it, and a class written with escapes is one careless
  // copy-paste away from becoming exactly that — which happened twice while
  // this function was being written.
  return [...JSON.stringify(fragment)]
    .map((ch) => {
      const c = ch.charCodeAt(0);
      return c >= DEL && c <= C1_END
        ? `\\u${c.toString(16).padStart(4, '0')}`
        : ch;
    })
    .join('');
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
 * Every `rm` argument a report emitted, as written.
 *
 * Deliberately does NOT skip leading `-…` words. The previous version consumed
 * `(?:\s+-[A-Za-z]+)*` as "flags" before capturing, so `rm -rf/x.txt` — a file
 * literally named `-rf` — was read as the flags `-rf` plus an argument
 * `/x.txt`, and the citation that IS the defect was parsed away before it could
 * be judged. Nothing HackMyAgent emits carries `rm` flags any more (#326
 * removed the only `rm -rf`), so a flag-looking word here is the finding.
 */
function rmArguments(out: string): Array<{ arg: string; line: string }> {
  const found: Array<{ arg: string; line: string }> = [];
  for (const line of out.split('\n')) {
    for (const m of line.matchAll(/\brm\s+([^`]+)/g)) {
      found.push({ arg: m[1].trim(), line });
    }
  }
  return found;
}

/**
 * Properties 2 and 3 — asked of a real shell, not of a rule copied from the
 * implementation.
 *
 * `plantedPaths` is the ground truth: the names the test put on disk. A citation
 * is correct exactly when a shell expands it to one word and that word is one of
 * them. `rm ~/evil.txt` expands to `$HOME/evil.txt`, which is not a planted
 * path, and that is the whole of #340's first half.
 */
export function assertCitationsQuoted(
  out: string,
  label: string,
  plantedPaths: readonly string[],
): void {
  for (const { arg, line } of rmArguments(out)) {
    // Property 3. A word beginning with `-` is read as options by every command
    // that takes them, whatever the quoting: the shell strips quotes before the
    // command sees the word, so `rm '-rf'` still passes `-rf` as a flag.
    expect(
      arg.startsWith('-'),
      `${label}: a citation names a path a command would read as a flag: ${JSON.stringify(line)}`,
    ).toBe(false);

    // Property 2. One argument in, one word out, and that word is the file —
    // asked of EVERY shell the reader might paste into, not just `sh`.
    //
    // #340's second half: asking only `sh` is a subset of the real expansion
    // set. zsh is the default shell on macOS and expands a leading `=` to a
    // resolved command path, so `rm =python3` deleted a binary while `sh` said
    // the citation was fine and this test stayed green.
    for (const shell of SHELLS) {
      let expanded: string;
      try {
        expanded = execFileSync(shell, ['-c', `printf '%s\\n' ${arg}`], {
          encoding: 'utf8',
          timeout: 30_000,
        });
      } catch {
        throw new Error(
          `${label}: ${shell} could not even parse the emitted citation: ${JSON.stringify(line)}`,
        );
      }
      assertOneWord(expanded, `${label} [${shell}]`, line, plantedPaths);
    }
  }
}

/** Every shell available on this machine that a reader could paste into. */
const SHELLS: string[] = ['sh', 'bash', 'zsh'].filter((sh) => {
  try {
    execFileSync('command', ['-v', sh], { stdio: 'ignore', shell: '/bin/sh' });
    return true;
  } catch {
    return false;
  }
});

function assertOneWord(
  expanded: string,
  label: string,
  line: string,
  plantedPaths: readonly string[],
): void {
  {
    const words = expanded.split('\n').filter((w) => w !== '');
    expect(
      words.length,
      `${label}: the citation is not one argument to a shell, so a filename is a `
      + `command: ${JSON.stringify(line)}`,
    ).toBe(1);
    // `./x` and `x` name the same file to every POSIX tool, and the `./` is
    // there deliberately (#340) so a path beginning with `-` cannot be read as
    // a flag. Comparing after dropping it keeps this an assertion about WHICH
    // FILE the shell reaches, which is the property, rather than about the
    // spelling the implementation chose — the mistake that made the previous
    // version of this helper agree with the bug.
    const named = words[0].startsWith('./') ? words[0].slice(2) : words[0];
    expect(
      plantedPaths,
      `${label}: a shell resolves the citation to ${JSON.stringify(words[0])}, which is `
      + `not the file the report is about: ${JSON.stringify(line)}`,
    ).toContain(named);
  }
}

/** The shells this run actually exercised, for a non-vacuity assertion. */
export const SHELLS_TESTED = SHELLS;

/**
 * Whether zsh exists on this machine at all.
 *
 * The zsh round trip is the one that catches EQUALS expansion (`rm =python3`
 * resolving to a command path), so a run that skips it covers less than a run
 * that does not — and the assertion that guards it must not be deleted just
 * because a machine lacks the shell.
 *
 * Splitting "zsh was not exercised" from "zsh is not installed" keeps that
 * guard sharp where it can fire: on any machine WITH zsh, failing to exercise
 * it is still a hard failure. On a machine without it — the Linux CI runner —
 * the coverage gap is real but is a property of the runner, not a regression
 * in the citation logic, and failing there only trains people to ignore the
 * job. `test-matrix.yml` runs macOS too, so zsh is exercised on every PR.
 */
export const ZSH_AVAILABLE = SHELLS.includes('zsh');

/** All of it, for one command's output. */
export function assertRenderSafe(
  out: string,
  label: string,
  plantedPaths: readonly string[] = [],
): void {
  assertNoRawControlBytes(out, label);
  assertNoSplitLines(out, label);
  assertCitationsQuoted(out, label, plantedPaths);
}
