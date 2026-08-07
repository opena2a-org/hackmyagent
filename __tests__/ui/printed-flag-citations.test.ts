/**
 * #372 — every CLI flag this tool prints at a user must be registered on the
 * command it is printed for.
 *
 * `__tests__/ui/concept-explainer-command-references.test.ts` was written for
 * #163 after the 0.22.0 `scan-soul --explain` dead end, precisely to stop this
 * class. It passed with three live instances, because its own docstring scopes
 * it to the concept-explainer registry:
 *
 *   src/cli.ts        `wild` says "use `--model` to pipe page content"    -> unknown option
 *   src/cli.ts        `fix-all` says "Uninstall with: … `--uninstall`"    -> unknown option
 *   src/registry/…    rate limit says "use `--skip-registry`"            -> unknown option
 *
 * The rule that gate was meant to enforce covers explainer AND finding-fix
 * strings; only the explainer half was built. Fixing the three strings and
 * leaving the walker narrow would sweep the reported surface again. This is
 * the other half: it walks every string literal under `src/`, attributes each
 * printed flag to a command, and asserts the flag is registered THERE.
 *
 * Widening it found a fourth instance the issue never named: 24 OASB
 * remediation strings printed `Run: hackmyagent secure --check <IDS>`, and
 * `--check` is not an option on `secure` (`error: unknown option '--check'`).
 * That is the return on building the guard rather than editing the strings.
 *
 * Two measured constraints on the walker, both of which defeat the obvious
 * implementation, are documented on the helper it uses:
 * `__tests__/helpers/printed-flag-citations.ts`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import {
  collectPrintedFlags,
  commandRegions,
  printedFlagsInSource,
} from '../helpers/printed-flag-citations';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '../..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const CLI_SRC = path.join(REPO_ROOT, 'src', 'cli.ts');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

function help(args: string[]): string | null {
  let out: string;
  try {
    out = execFileSync(process.execPath, [CLI, ...args, '--help'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 15_000,
      env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
    }).replace(STRIP_ANSI, '');
  } catch {
    return null;
  }
  // Exit 0 is not proof it ran. `hackmyagent status --help` — `status` is a
  // subcommand of `nanomind`, not a top-level command — exits 0 and prints
  // NOTHING, so a lookup that only checked the exit code returned an empty
  // flag set and passed every citation under that command vacuously.
  return out.trim().length > 0 ? out : null;
}

/**
 * Commands are read from the `.command(…)` registrations rather than from the
 * "Commands:" block of `--help`. Parsing the help block picks up continuation
 * lines of multi-line descriptions, which produced verbs like `and`, `for` and
 * `so` — and a bogus verb makes the attribution wrong in BOTH directions: it
 * invents a command for a flag that has none, and it hides the enclosing
 * command that should have been checked.
 */
function registeredVerbs(): Set<string> {
  return new Set(commandRegions(readFileSync(CLI_SRC, 'utf8')).map((m) => m.name));
}

/** name -> the argv path that reaches it (`status` -> `nanomind status`). */
function verbPaths(): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const r of commandRegions(readFileSync(CLI_SRC, 'utf8'))) out.set(r.name, r.path);
  return out;
}

let verbs: Set<string>;
let paths: Map<string, string[]>;
const flagCache = new Map<string, Set<string> | null>();

/** `null` when the command's help could not be read at all. */
function flagsOn(verb: string): Set<string> | null {
  if (flagCache.has(verb)) return flagCache.get(verb)!;
  const h = help(paths.get(verb) ?? [verb]);
  const out = h === null ? null : new Set<string>();
  if (h && out) for (const m of h.matchAll(/(--[a-z][a-z0-9-]+)/g)) out.add(m[1]);
  flagCache.set(verb, out);
  return out;
}

function unionOfAllFlags(): Set<string> {
  const out = new Set<string>();
  for (const v of verbs) for (const f of flagsOn(v) ?? []) out.add(f);
  const root = help([]);
  if (root) for (const m of root.matchAll(/(--[a-z][a-z0-9-]+)/g)) out.add(m[1]);
  return out;
}

beforeAll(() => { verbs = registeredVerbs(); paths = verbPaths(); });

describe('#372 the walker sees what it claims to see', () => {
  it('reads the command registry', () => {
    expect(verbs.size, 'no `.command(…)` registrations found in src/cli.ts').toBeGreaterThan(15);
    expect(verbs.has('secure')).toBe(true);
    expect(verbs.has('check')).toBe(true);
    // A verb the old help-block parser invented. If this ever becomes true the
    // verb source has regressed to parsing prose.
    expect(verbs.has('and')).toBe(false);
  });

  it('every registered command answers --help on the path that reaches it', () => {
    // Otherwise `flagsOn` returns an empty set and every citation on that
    // command passes for the wrong reason. `nanomind status` is why this
    // asserts on the PATH and why `help()` rejects an empty body: as a bare
    // `status --help` it exits 0 and prints nothing.
    if (!existsSync(CLI)) return;
    const silent = [...verbs].filter((v) => flagsOn(v) === null);
    expect(silent, 'these commands produced no --help, so their flags cannot be checked').toEqual([]);
  });

  it('resolves subcommands to the path that runs them', () => {
    expect(paths.get('check')).toEqual(['check']);
    expect(paths.get('status'), '`status` is registered on the `nanomind` sub-program').toEqual(['nanomind', 'status']);
  });

  it('finds a substantial number of printed flags', () => {
    // Non-vacuity. A broken extractor returns [], and [] passes the assertion
    // this suite exists to make.
    const found = collectPrintedFlags({ repoRoot: REPO_ROOT, verbs });
    expect(found.length, 'the extractor found no printed flags at all').toBeGreaterThan(60);
  });

  it('catches a planted dead citation', () => {
    // A plant, not a count. The assertion below is "nothing is wrong", which
    // is also what a walker that has stopped working reports.
    const planted = printedFlagsInSource({
      src: [
        "const lines: string[] = [];",
        "lines.push(`  Try: ${CLI_PREFIX} secure . --not-a-real-flag`);",
      ].join('\n'),
      file: 'planted.ts',
      verbs,
    });
    const hit = planted.find((f) => f.flag === '--not-a-real-flag');
    expect(hit, 'the walker missed a flag inside a template literal in an array push').toBeDefined();
    expect(hit!.command, 'the walker did not attribute the flag to the command named beside it').toBe('secure');
  });

  it('attributes a bare flag to the command that prints it', () => {
    // The `--model` shape: printed advice naming no command. Attribution has
    // to come from the enclosing registration or the citation is unowned.
    const src = [
      "program",
      "  .command('wild')",
      "  .action(() => {",
      "    console.log(`use --not-a-real-flag to do the thing`);",
      "  });",
    ].join('\n');
    const planted = printedFlagsInSource({
      src, file: 'planted-cli.ts', verbs, marks: commandRegions(src),
    });
    const hit = planted.find((f) => f.flag === '--not-a-real-flag');
    expect(hit?.command).toBe('wild');
    expect(hit?.inferred).toBe(true);
  });

  it('does not claim another tool\'s flags', () => {
    // The other direction. A walker that flags every `--word` in every string
    // turns red on `npm audit --audit-level=high` and gets switched off.
    const planted = printedFlagsInSource({
      src: "console.log('Run: npm audit --audit-level=high, then grep -r x --include=\"*.js\"');",
      file: 'planted-foreign.ts',
      verbs,
    });
    expect(planted.map((f) => f.flag)).toEqual([]);
  });

  it('is not blinded by an English word that is also a program name', () => {
    // The other half of the foreign-executable rule, and the direction that
    // costs coverage rather than causing noise. With `go` and `find` on the
    // skip list, both of these advice lines were silently dropped — a dead
    // citation could hide behind a common verb.
    for (const prose of [
      "console.log('If you go further, use --not-a-real-flag.');",
      "console.log('To find more, use --not-a-real-flag.');",
    ]) {
      const planted = printedFlagsInSource({ src: prose, file: 'planted-prose.ts', verbs });
      expect(planted.map((f) => f.flag), prose).toEqual(['--not-a-real-flag']);
    }
  });

  it('does not read CSS custom properties as flags', () => {
    const planted = printedFlagsInSource({
      src: "console.log(`<style>:root{--bg-primary:#000}.x{color:var(--bg-primary)}</style>`);",
      file: 'planted-css.ts',
      verbs,
    });
    expect(planted.map((f) => f.flag)).toEqual([]);
  });
});

describe('#372 every printed flag is registered where it is printed', () => {
  it('cites no flag that its own command does not accept', () => {
    if (!existsSync(CLI)) return;
    const union = unionOfAllFlags();
    expect(union.size, 'no flags parsed out of --help').toBeGreaterThan(20);

    const dead = collectPrintedFlags({ repoRoot: REPO_ROOT, verbs })
      .filter((f) => (f.command ? !(flagsOn(f.command) ?? new Set()).has(f.flag) : !union.has(f.flag)))
      .map((f) => `${f.file}:${f.line} prints ${f.flag}`
        + (f.command
          ? ` as \`${f.command} ${f.flag}\`, but ${f.flag} is not registered on ${f.command}`
          : `, which is not registered on any command`)
        + `\n      ${f.text}`);

    expect(
      dead,
      'a printed string cites a flag the user cannot run. Fix the string to name a '
      + 'command and flag that exist — do not narrow this walker.\n  - '
      + dead.join('\n  - '),
    ).toEqual([]);
  });

  it('explicit regressions: the four instances this test was built for', () => {
    if (!existsSync(CLI)) return;
    const cli = readFileSync(CLI_SRC, 'utf8');
    const registry = readFileSync(path.join(REPO_ROOT, 'src', 'registry', 'client.ts'), 'utf8');
    const oasb = readFileSync(path.join(REPO_ROOT, 'src', 'benchmarks', 'oasb-1.ts'), 'utf8');

    // Named so a revert reads as a regression rather than as a count moving.
    expect(cli, '`fix-all --uninstall` was never a registered option').not.toContain('fix-all ${citationTarget(directory || \'.\')} --uninstall');
    expect(registry, 'the real flag is --no-registry').not.toContain('--skip-registry');
    expect(oasb, '`secure --check` is not a registered option').not.toContain('secure --check');
    expect(help(['wild']) ?? '', 'if `wild` gains --model the advice may name it directly again').not.toMatch(/--model\b/);
  });
});
