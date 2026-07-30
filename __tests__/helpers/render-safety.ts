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
  scan: 'scans an external network endpoint; its target is a host the user typed, not a path from a scanned tree',
  check: 'renders-paths',
  detect: 'renders-paths',
  'scan-soul': 'renders-paths',
  'harden-soul': 'renders-paths',
  wild: 'renders-paths',
  rollback: 'renders-paths',
  'fix-all': 'renders-paths',
  'secure-openclaw': 'renders-paths',
  'secure-nemoclaw': 'renders-paths',
  'create-skill': 'writes a new tree from arguments the user typed; no scanned path is rendered',
  'init-mcp': 'writes a config from arguments the user typed; no scanned path is rendered',
  attack: 'sends payloads to an endpoint; renders payload names, not filesystem paths',
  'red-team': 'sends payloads to an endpoint; renders payload names, not filesystem paths',
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
};

/**
 * Property 1 — no raw control byte from the scanned tree.
 *
 * The tool's own layout uses newline and tab, so those two cannot be judged
 * here; property 1b covers an injected newline by asserting no line splits.
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

    // Property 2. One argument in, one word out, and that word is the file.
    let expanded: string;
    try {
      expanded = execFileSync('sh', ['-c', `printf '%s\\n' ${arg}`], {
        encoding: 'utf8',
        timeout: 30_000,
      });
    } catch {
      throw new Error(
        `${label}: a shell could not even parse the emitted citation: ${JSON.stringify(line)}`,
      );
    }
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
