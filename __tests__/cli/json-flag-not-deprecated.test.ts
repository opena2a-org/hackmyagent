/**
 * HMA-36 — `--json` is shorthand for `--format json`, and nothing may call it
 * deprecated again.
 *
 * `secure --help` said "(deprecated: use --format json)" and `attack --help`
 * said "(deprecated alias of --format json)" from 0.8.0 through 0.32.0, while
 * the README cited `--json` throughout as the ordinary machine-output
 * spelling. The flag was never deprecated: no warning fired, no removal was
 * scheduled, and the alias is kept indefinitely. This suite pins the ruling
 * so a future command cannot re-deprecate it from a help string, and a README
 * line cannot cite a flag its command does not register.
 *
 * Mechanism: the real Commander `program` from src/cli.ts, walked recursively
 * over `program.commands` — hidden commands (`secure-openclaw`,
 * `secure-nemoclaw`) and nested registrations (`eval oracle`, `nanomind
 * setup|status`) included. A help-text walk would miss the hidden commands,
 * and a source grep cannot see `eval`'s `addCommand`-built subcommand; the
 * registry Commander actually dispatches on can do both. src/cli.ts does not
 * export its program, so the root is captured the way #372's walker captures
 * attribution — structurally: `showHelpAfterError` is called exactly once in
 * cli.ts, on the root, immediately after construction. The module's entry
 * IIFE is neutralised for the import (argv trimmed to two entries,
 * `process.exit` a no-op, stdout/stderr swallowed) so registration happens
 * and dispatch does not.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFileSync, mkdtempSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Command } from 'commander';

const REPO_ROOT = path.join(__dirname, '..', '..');

/** The canonical help string; byte-identical on `secure` and `attack`. */
const SHORTHAND = 'Output as JSON (shorthand for --format json)';

interface Walked {
  /** argv path from the root, e.g. ['eval', 'oracle']. */
  path: string[];
  command: Command;
}

let root: Command | undefined;
let walked: Walked[] = [];

const saved = {
  argv: process.argv,
  exit: process.exit,
  home: process.env.HOME,
  stdoutWrite: process.stdout.write,
  stderrWrite: process.stderr.write,
  showHelpAfterError: Command.prototype.showHelpAfterError,
};

function walk(cmd: Command, crumbs: string[]): Walked[] {
  const self: Walked = { path: [...crumbs, cmd.name()], command: cmd };
  return [self, ...cmd.commands.map((c) => walk(c as Command, self.path)).flat()];
}

beforeAll(async () => {
  const captured: Command[] = [];
  Command.prototype.showHelpAfterError = function (this: Command, ...args: [(string | boolean)?]) {
    captured.push(this);
    return saved.showHelpAfterError.apply(this, args);
  };
  // Two-entry argv: the entry IIFE prints help and exits instead of
  // dispatching a command; with `process.exit` a no-op that is inert.
  process.argv = [process.argv[0], 'cli.ts'];
  process.exit = ((code?: number) => undefined as never) as typeof process.exit;
  process.env.HOME = mkdtempSync(path.join(os.tmpdir(), 'hma36-home-'));
  process.env.OPENA2A_TELEMETRY = 'off';
  // The IIFE's help output is noise, not a result; vitest reports over IPC,
  // so swallowing the raw streams loses nothing.
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;

  await import('../../src/cli');

  // Registration is complete once the entry IIFE has added `telemetry`, the
  // one command registered after its first `await`.
  const rootHasTelemetry = () =>
    captured[0]?.commands.some((c) => c.name() === 'telemetry') ?? false;
  for (let waited = 0; !rootHasTelemetry() && waited < 10_000; waited += 25) {
    await new Promise((r) => setTimeout(r, 25));
  }
  // Let the IIFE's own parse of the two-entry argv settle before any test
  // runs, so its writes land while the streams are still swallowed.
  await new Promise((r) => setTimeout(r, 250));

  root = captured[0];
  walked = root ? root.commands.map((c) => walk(c as Command, [])).flat() : [];
});

afterAll(() => {
  process.argv = saved.argv;
  process.exit = saved.exit;
  process.env.HOME = saved.home;
  process.stdout.write = saved.stdoutWrite;
  process.stderr.write = saved.stderrWrite;
  Command.prototype.showHelpAfterError = saved.showHelpAfterError;
});

const jsonOpt = (c: Command) => c.options.find((o) => o.long === '--json');
const formatOpt = (c: Command) => c.options.find((o) => o.long === '--format');
const label = (w: Walked) => w.path.join(' ');

const withJson = () => walked.filter((w) => jsonOpt(w.command));
const withFormat = () => walked.filter((w) => formatOpt(w.command));

describe('HMA-36 `--json` is shorthand, never deprecated, across the whole command tree', () => {
  it('HMA-36.AC3 captures the real program and walks every registration, hidden and nested included', () => {
    // Non-vacuity for everything below. If the capture hook stops firing —
    // the `showHelpAfterError` call moves, the entry IIFE changes shape —
    // every per-command assertion would hold over an empty list, which is
    // the failure mode this test exists to prevent.
    expect(root, 'src/cli.ts no longer constructs its program the way this capture expects').toBeDefined();
    const names = walked.map(label);
    expect(names).toContain('secure');
    expect(names).toContain('secure-openclaw'); // hidden
    expect(names).toContain('secure-nemoclaw'); // hidden
    expect(names).toContain('eval oracle'); // nested via addCommand
    expect(names).toContain('nanomind status'); // nested via a sub-program handle
    expect(names).toContain('telemetry'); // registered inside the entry IIFE

    // The measured population: 16 commands register `--json`, 3 register
    // `--format` (secure, attack, eval oracle); 14 are `--json`-only, 2
    // carry both, 1 is `--format`-only. A command gaining or losing either
    // flag moves a count here on purpose — re-measure, then retune.
    expect(withJson().map(label).sort()).toHaveLength(16);
    expect(withFormat().map(label).sort()).toEqual(['attack', 'eval oracle', 'secure']);
    expect(withJson().filter((w) => !formatOpt(w.command))).toHaveLength(14);
    expect(withJson().filter((w) => formatOpt(w.command)).map(label).sort()).toEqual(['attack', 'secure']);
  });

  it('HMA-36.AC3 (A) no --json description anywhere in the tree matches /deprecat/i', () => {
    for (const w of withJson()) {
      expect(
        jsonOpt(w.command)!.description,
        `\`${label(w)}\` describes --json as deprecated; it is shorthand for --format json (HMA-36)`,
      ).not.toMatch(/deprecat/i);
    }
    expect(withJson().length).toBeGreaterThan(0);
  });

  it('HMA-36.AC3 (B) a --json-only command\'s help never cites --format', () => {
    // `check --json` has no `--format` to be shorthand FOR; pointing its
    // help at a flag the command refuses is the dead end #372 measures.
    // Green since 59088c70 and held green: the ratchet over future commands.
    for (const w of withJson().filter((w) => !formatOpt(w.command))) {
      expect(
        jsonOpt(w.command)!.description,
        `\`${label(w)}\` does not register --format, so its --json help must not cite it`,
      ).not.toContain('--format');
    }
  });

  it('HMA-36.AC3 (B) where --format is registered, the --json help is exactly the canonical shorthand string', () => {
    for (const w of withJson().filter((w) => formatOpt(w.command))) {
      expect(jsonOpt(w.command)!.description, `\`${label(w)}\` registers both flags`).toBe(SHORTHAND);
    }
  });

  // README citation gates (C)/(D). A code line is read only when its first
  // command token — after any list or YAML prefix such as `      - run: `, a
  // `$ ` prompt or an inline-code backtick — is `hackmyagent` or
  // `npx hackmyagent`. That token rule is what excludes
  // `npm view hackmyagent dist.attestations --json` (README.md:89): the
  // first command token there is `npm`, whose `--json` is npm's own.
  interface Citation {
    line: number;
    text: string;
    /** Tokens after `hackmyagent`, e.g. ['secure', '--ci', '--json', '.']. */
    tokens: string[];
  }

  function readmeCitations(flag: string): Citation[] {
    const readme = readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf8');
    const found: Citation[] = [];
    readme.split('\n').forEach((raw, i) => {
      if (!raw.includes(flag)) return;
      const stripped = raw
        .replace(/^[\s>]*(?:[-*]\s+)?(?:[A-Za-z_][\w-]*:\s+)?/, '') // list / YAML prefix
        .replace(/^\$\s+/, '') // shell prompt
        .replace(/^`/, ''); // inline-code opener
      const tokens = stripped.split(/\s+/);
      let at = 0;
      if (tokens[at] === 'npx') at += 1;
      if (tokens[at] !== 'hackmyagent') return;
      found.push({ line: i + 1, text: raw.trim(), tokens: tokens.slice(at + 1) });
    });
    return found;
  }

  /** Deepest command the citation's leading tokens name: `eval oracle --format json` resolves to `eval oracle`. */
  function resolveCommand(tokens: string[]): Walked | undefined {
    let depth = 0;
    let at: Walked | undefined;
    for (const token of tokens) {
      const next = walked.find(
        (w) => w.path.length === depth + 1
          && (at === undefined || label(w).startsWith(`${label(at)} `))
          && (w.path[depth] === token || w.command.aliases().includes(token)),
      );
      if (!next) break;
      at = next;
      depth += 1;
    }
    return at;
  }

  it('HMA-36.AC3 (C) every README hackmyagent line citing --json names a command that registers --json', () => {
    const citations = readmeCitations('--json');
    // Non-vacuity: the README's CI examples cite `--json` today; an empty
    // walk here means the line reader broke, not that the README went quiet.
    expect(citations.length).toBeGreaterThan(0);
    for (const cite of citations) {
      const command = resolveCommand(cite.tokens);
      expect(
        command && jsonOpt(command.command),
        `README.md:${cite.line} cites --json against \`${cite.tokens[0] ?? ''}\`, `
        + `which does not register it: ${cite.text}`,
      ).toBeTruthy();
    }
  });

  it('HMA-36.AC3 (D) every README hackmyagent line citing --format names a command that registers --format', () => {
    for (const cite of readmeCitations('--format')) {
      const command = resolveCommand(cite.tokens);
      expect(
        command && formatOpt(command.command),
        `README.md:${cite.line} cites --format against \`${cite.tokens[0] ?? ''}\`, `
        + `which does not register it: ${cite.text}`,
      ).toBeTruthy();
    }
  });
});
