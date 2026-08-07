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
  collectMarkdownFlags,
  commandRegions,
  printedFlagsInSource,
  printedFlagsInMarkdown,
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

  it('reads README.md and docs/, not only src/', () => {
    // #434 — `docs/use-cases/openclaw-security.md:61` cited `check --sign`,
    // unregistered, and #372's gate did not miss it: markdown has no string
    // literals, so no walker read the file. Non-vacuity first: the markdown
    // half must find real citations, because [] passes the dead-flag rule.
    const md = collectMarkdownFlags({ repoRoot: REPO_ROOT, verbs });
    expect(md.length, 'the markdown extractor found no cited flags at all').toBeGreaterThan(10);
    expect(new Set(md.map((f) => f.file)).size, 'only one markdown file was read').toBeGreaterThan(1);
    // And the combined walk is strictly larger than the source-only walk.
    expect(collectPrintedFlags({ repoRoot: REPO_ROOT, verbs }).length).toBeGreaterThan(md.length);
  });

  it('catches a dead citation planted in markdown', () => {
    // The plant, in each of the two shapes documentation uses.
    const fenced = printedFlagsInMarkdown({
      src: ['Run it:', '', '```bash', '$ hackmyagent secure . --not-a-real-flag', '```'].join('\n'),
      file: 'planted.md',
      verbs,
    });
    expect(fenced.find((f) => f.flag === '--not-a-real-flag')?.command).toBe('secure');

    const inline = printedFlagsInMarkdown({
      src: 'Use `hackmyagent check ./x --not-a-real-flag` to verify.',
      file: 'planted.md',
      verbs,
    });
    expect(inline.find((f) => f.flag === '--not-a-real-flag')?.command).toBe('check');
  });

  it('does not read markdown prose as an invocation', () => {
    // The over-correction direction. A hyphenated phrase in a sentence, and a
    // flag belonging to another program in a pipeline, must not be attributed
    // to this CLI — that is the misattribution the segment rule in the source
    // walker exists to prevent, and the markdown walker must not reintroduce it.
    const prose = [
      'The scan is fully self-contained -- no data leaves your machine.',
      '',
      '```bash',
      'npm audit --json | jq .',
      'git diff --stat',
      '```',
    ].join('\n');
    expect(printedFlagsInMarkdown({ src: prose, file: 'planted.md', verbs })).toEqual([]);
  });

  it('does not let a flag leak across invocations on ONE line', () => {
    // Adversarial review finding: a line holds several invocations
    // (`a && b`, `a; b`, `a | b`) and taking every flag after the FIRST verb
    // attributed the second command's flags to the first. That is a false
    // citation the gate would then report against the wrong command.
    for (const sep of ['&&', ';', '|']) {
      const line = `hackmyagent check ./x ${sep} hackmyagent attack --totally-bogus-flag`;
      const found = printedFlagsInMarkdown({ src: `\`${line}\``, file: 'planted.md', verbs });
      const hit = found.find((f) => f.flag === '--totally-bogus-flag');
      expect(hit, `separator ${sep}: the flag was not found at all`).toBeDefined();
      expect(hit!.command, `separator ${sep}: attributed to the wrong command`).toBe('attack');
    }
  });

  it('reads every code-block form markdown actually uses', () => {
    // Review finding: only ``` fences were read, so ~~~ fences, indented
    // blocks and a versioned `npx hackmyagent@latest` launcher were all
    // invisible — a dead citation in any of them would pass the gate.
    const cases: Array<[string, string]> = [
      ['tilde fence', '~~~bash\nhackmyagent check --totally-bogus-flag\n~~~'],
      ['indented block', 'Run it:\n\n    hackmyagent check --totally-bogus-flag\n'],
      ['versioned npx', '`npx hackmyagent@latest check --totally-bogus-flag`'],
      ['bunx launcher', '`bunx hackmyagent check --totally-bogus-flag`'],
    ];
    for (const [label, src] of cases) {
      const found = printedFlagsInMarkdown({ src, file: 'planted.md', verbs });
      expect(
        found.find((f) => f.flag === '--totally-bogus-flag')?.command,
        `${label}: the walker did not read this code form`,
      ).toBe('check');
    }
  });

  it('does not let a flag leak across lines of one fenced block', () => {
    // A fenced block holds many invocations. Reading the block as one segment
    // would attribute every flag in it to the first command named.
    const block = [
      '```bash',
      'hackmyagent secure . --fix',
      'hackmyagent detect --json',
      '```',
    ].join('\n');
    const found = printedFlagsInMarkdown({ src: block, file: 'planted.md', verbs });
    expect(found.find((f) => f.flag === '--fix')?.command).toBe('secure');
    expect(found.find((f) => f.flag === '--json')?.command).toBe('detect');
    expect(found.filter((f) => f.command === 'secure').map((f) => f.flag)).toEqual(['--fix']);
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
