/**
 * Every command a tape types on screen is one the CLI registers.
 *
 * A recording is rendered from a `.tape`, and a tape that types a flag the CLI
 * does not have renders an error into a GIF that nobody re-reads. The gates
 * over documented commands read Markdown and source strings
 * (`documented-command-arguments.test.ts` for arguments,
 * `__tests__/ui/printed-flag-citations.test.ts` for flags); a tape is neither,
 * so its typed lines are held here by the same two mechanisms: the invocation
 * expression of the first, and the registry of the second, which is the
 * `.command(...)` registrations in src/cli.ts plus the flags each command's
 * `--help` prints from the built CLI.
 *
 * Scope: every `Type` line outside a `Hide`..`Show` block in every tape under
 * docs/. A line typed inside such a block is setup the recording does not
 * show, and is not read.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { commandRegions } from '../helpers/printed-flag-citations';
import { parseTape, tapeFiles } from '../helpers/tape';

beforeAll(assertDistFresh);

const REPO_ROOT = path.join(__dirname, '..', '..');
const TAPES = tapeFiles(path.join(REPO_ROOT, 'docs'));
const REGIONS = commandRegions(readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf8'));
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

interface Invocation {
  /** Flags typed before the command name: they belong to the program. */
  rootFlags: string[];
  /** The command name, or undefined when the line types flags only (`hackmyagent --version`). */
  verb: string | undefined;
  args: string[];
}

const isFlag = (token: string): boolean => /^-{1,2}[A-Za-z]/.test(token);

/**
 * Every `hackmyagent ...` invocation in one typed line. A line is split on the
 * shell operators the documented-command-arguments suite splits on, so the
 * `head -29` after a pipe is not read as an argument of the command before it.
 */
function invocations(line: string): Invocation[] {
  const found: Invocation[] = [];
  for (const segment of line.replace(/\s#.*$/, '').split(/&&|\|\||[|;]/)) {
    const m = segment.match(/(?:^|\s)(?:(?:npx|pnpm dlx|bunx)\s+)?(?:hackmyagent|hma)(?:@[\w.-]+)?((?:\s+\S+)*)\s*$/);
    if (!m) continue;
    const tokens = m[1].trim().split(/\s+/).filter(Boolean);
    const at = tokens.findIndex((t) => !isFlag(t));
    found.push(at === -1
      ? { rootFlags: tokens, verb: undefined, args: [] }
      : { rootFlags: tokens.slice(0, at), verb: tokens[at], args: tokens.slice(at + 1) });
  }
  return found;
}

const helpCache = new Map<string, Set<string> | null>();

/** The flags `hackmyagent <argv path> --help` prints, or null when it prints nothing. */
function flagsOn(argvPath: string[]): Set<string> | null {
  const key = argvPath.join(' ');
  if (helpCache.has(key)) return helpCache.get(key)!;
  let out = '';
  try {
    out = execFileSync(process.execPath, [BUILT_CLI, ...argvPath, '--help'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 15_000,
      env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
    }).replace(STRIP_ANSI, '');
  } catch {
    out = '';
  }
  const flags = out.trim().length === 0
    ? null
    : new Set([...out.matchAll(/(?<![\w-])(--[a-z][a-z0-9-]*|-[A-Za-z])(?![\w-])/g)].map((m) => m[1]));
  helpCache.set(key, flags);
  return flags;
}

/** What is wrong with the lines one tape types on screen; empty when nothing is. */
function problems(file: string, src: string): string[] {
  const out: string[] = [];
  for (const line of parseTape(src).typed) {
    for (const inv of invocations(line)) {
      const where = `${file}: \`${line}\``;
      let argvPath: string[] = [];
      let args = inv.args;
      if (inv.verb !== undefined) {
        const child = REGIONS.find((r) => r.path.length === 2 && r.path[0] === inv.verb && r.path[1] === args[0]);
        const top = REGIONS.find((r) => r.path.length === 1 && r.name === inv.verb);
        if (!child && !top) {
          out.push(`${where}: \`${inv.verb}\` is not a registered command`);
          continue;
        }
        argvPath = child ? child.path : top!.path;
        if (child) args = args.slice(1);
      }
      const typedFlags = [
        ...inv.rootFlags.map((flag) => ({ flag, on: [] as string[] })),
        ...args.filter(isFlag).map((flag) => ({ flag, on: argvPath })),
      ];
      for (const { flag, on } of typedFlags) {
        const name = flag.split('=')[0];
        const registered = flagsOn(on);
        const label = on.length > 0 ? `\`${on.join(' ')}\`` : 'the program';
        if (registered === null) out.push(`${where}: the help of ${label} could not be read`);
        else if (!registered.has(name)) out.push(`${where}: \`${name}\` is not an option of ${label}`);
      }
    }
  }
  return out;
}

const read = (file: string): string => readFileSync(file, 'utf8');
const rel = (file: string): string => path.relative(REPO_ROOT, file).split(path.sep).join('/');

describe('tape commands are registered', () => {
  it('finds the tapes and reads an invocation from each (non-vacuity)', () => {
    expect(TAPES.map(rel)).toContain('docs/vhs/secure.tape');
    expect(TAPES.length).toBeGreaterThanOrEqual(4);
    for (const file of TAPES) {
      const typed = parseTape(read(file)).typed;
      expect(typed.flatMap(invocations).length, `${rel(file)} types no hackmyagent command`).toBeGreaterThan(0);
    }
    expect(REGIONS.length).toBeGreaterThan(15);
    expect(flagsOn(['secure'])?.has('--fix')).toBe(true);
  });

  it('every command a tape types on screen is registered, with options its --help lists', () => {
    expect(TAPES.flatMap((file) => problems(rel(file), read(file)))).toEqual([]);
  });

  it('reports an option the command does not register, and a command that is not registered', () => {
    const tape = read(path.join(REPO_ROOT, 'docs', 'vhs', 'secure.tape'));
    expect(tape).toContain('Type "npx hackmyagent secure --fix"');
    const flag = tape.replace('Type "npx hackmyagent secure --fix"', 'Type "npx hackmyagent secure --fix --no-such-flag"');
    expect(problems('planted.tape', flag)).toEqual([
      'planted.tape: `npx hackmyagent secure --fix --no-such-flag`: `--no-such-flag` is not an option of `secure`',
    ]);
    const verb = tape.replace('Type "npx hackmyagent secure --fix"', 'Type "npx hackmyagent no-such-command --fix"');
    expect(problems('planted.tape', verb)).toEqual([
      'planted.tape: `npx hackmyagent no-such-command --fix`: `no-such-command` is not a registered command',
    ]);
  });

  it('reads an option of a subcommand against that subcommand, and one before the command against the program', () => {
    expect(problems('planted.tape', 'Type "hackmyagent nanomind status --no-such-flag"')).toEqual([
      'planted.tape: `hackmyagent nanomind status --no-such-flag`: `--no-such-flag` is not an option of `nanomind status`',
    ]);
    expect(problems('planted.tape', 'Type "hackmyagent --version"')).toEqual([]);
    expect(problems('planted.tape', 'Type "hackmyagent --no-such-flag secure"')).toEqual([
      'planted.tape: `hackmyagent --no-such-flag secure`: `--no-such-flag` is not an option of the program',
    ]);
  });

  it('does not read a line typed inside a Hide..Show block, or what follows a pipe', () => {
    expect(problems('planted.tape', 'Hide\nType "hackmyagent secure --no-such-flag"\nShow\nType "hackmyagent secure | head --no-such-flag"')).toEqual([]);
  });
});
