/**
 * Every `hackmyagent` command the NemoClaw scanner prints is one that runs.
 *
 * HMA-NMC-040 told the user to run `npx hackmyagent scan --ci /app` inside
 * the sandbox. `scan` takes a hostname, an IP address or a URL and registers
 * no `--ci`, so the line exited 1 with `Cannot parse "/app" as a target`.
 *
 * `__tests__/ui/printed-flag-citations.test.ts` walks this file and did not
 * see it: the line begins `docker exec … npx`, and a segment that names a
 * foreign executable is read as another tool's command line and skipped. That
 * skip is deliberate there, so this walk is scoped to the scanner instead of
 * changing it. It finds each `hackmyagent <verb>` however it is launched and
 * checks it against the built CLI's own `--help`: the verb is a top-level
 * command, every flag after it is listed on that command, and a path argument
 * goes to a command whose usage takes a directory.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { commandRegions, stringLiterals } from '../helpers/printed-flag-citations';
import { tempDir } from '../helpers/temp-dir';

// The scanner's shell probes (`docker`, `ps`, `which`) are stubbed to fail,
// which it reads as "not installed"; a `~/.nemoclaw` directory is enough for
// it to run every layer. `execFileSync`, used for `--help`, stays real.
vi.mock('child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('child_process')>()),
  execSync: () => {
    throw new Error('shell probes are disabled in this test');
  },
}));

const REPO_ROOT = path.resolve(__dirname, '../..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const SCANNER = path.join(REPO_ROOT, 'src', 'hardening', 'nemoclaw-scanner.ts');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

/** `hackmyagent <verb> <rest of the invocation>`, with or without a launcher before it. */
const INVOCATION = /\bhackmyagent(?:@[\w.-]+)?\s+([a-z][a-z0-9-]*)([^;|&\n]*)/g;
/** A usage argument that names a directory, e.g. `[directory]`. */
const DIRECTORY_ARG = /[<[](?:directory|dir|path)(?:\.\.\.)?[>\]]/;
/** An argument the shell would pass as a path: `/app`, `.`, `./x`, `~/x`. */
const PATH_ARG = /^(?:\/|\.{1,2}(?:\/|$)|~(?:\/|$))/;

interface Cli {
  /** Top-level commands: the ones `hackmyagent <verb>` reaches. */
  verbs: ReadonlySet<string>;
  /** `<verb> --help`, or null when it printed nothing. */
  help(verb: string): string | null;
}

function verbsIn(text: string): string[] {
  return [...text.matchAll(INVOCATION)].map((m) => m[1]);
}

/** What is wrong with each `hackmyagent` invocation in `text`; [] when every one runs. */
function citationProblems(text: string, cli: Cli): string[] {
  const problems: string[] = [];
  for (const m of text.matchAll(INVOCATION)) {
    const [cited, verb, rest] = m;
    if (!cli.verbs.has(verb)) {
      problems.push(`\`${cited.trim()}\`: \`${verb}\` is not a hackmyagent command`);
      continue;
    }
    const help = cli.help(verb);
    if (help === null) {
      problems.push(`\`${cited.trim()}\`: \`${verb} --help\` printed nothing, so its flags cannot be checked`);
      continue;
    }
    const flags = new Set([...help.matchAll(/(--[a-z][a-z0-9-]+)/g)].map((f) => f[1]));
    const usage = /^Usage:.*$/m.exec(help)?.[0] ?? '';
    // Only whitespace-separated tokens: `secure.` at the end of a sentence is
    // not a path argument.
    for (const t of rest.matchAll(/\s(\S+)/g)) {
      const token = t[1];
      if (token.startsWith('--')) {
        const flag = token.split('=')[0];
        if (!flags.has(flag)) problems.push(`\`${cited.trim()}\`: ${flag} is not an option of \`${verb}\``);
      } else if (PATH_ARG.test(token) && !DIRECTORY_ARG.test(usage)) {
        problems.push(`\`${cited.trim()}\`: \`${verb}\` does not take a directory (${usage.trim()}), so ${token} is not scanned`);
      }
    }
  }
  return problems;
}

function builtCli(): Cli {
  const regions = commandRegions(readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf8'));
  const verbs = new Set(regions.filter((r) => r.path.length === 1).map((r) => r.name));
  const cache = new Map<string, string | null>();
  return {
    verbs,
    help(verb) {
      if (!cache.has(verb)) {
        let out: string | null;
        try {
          out = execFileSync(process.execPath, [CLI, verb, '--help'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
            timeout: 15_000,
            env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
          }).replace(STRIP_ANSI, '');
        } catch {
          out = null;
        }
        cache.set(verb, out && out.trim().length > 0 ? out : null);
      }
      return cache.get(verb)!;
    },
  };
}

/** Run the scanner against a HOME that holds `~/.nemoclaw` and nothing else. */
async function scanFindings(): Promise<Array<{ checkId: string; message?: string; description?: string; fix?: string }>> {
  const root = tempDir('nmc-fix-');
  const realHome = process.env.HOME;
  try {
    const home = path.join(root, 'home');
    const target = path.join(root, 'target');
    mkdirSync(path.join(home, '.nemoclaw'), { recursive: true });
    mkdirSync(target, { recursive: true });
    process.env.HOME = home;
    vi.resetModules();
    const { NemoClawScanner } = await import('../../src/hardening/nemoclaw-scanner');
    return (await new NemoClawScanner().scan(target)) as any;
  } finally {
    process.env.HOME = realHome;
  }
}

describe('the citation walk sees what it claims to see', () => {
  it('catches the line HMA-NMC-040 shipped, on the flag and on the path', () => {
    // A plant, not a count: after the fix the tree holds no violation, which
    // is also what a walk that has stopped working reports.
    const cli: Cli = {
      verbs: new Set(['scan', 'secure']),
      help: (verb) => (verb === 'scan'
        ? 'Usage: hackmyagent scan [options] <target>\n\nOptions:\n  --json\n'
        : 'Usage: hackmyagent secure [options] [directory]\n\nOptions:\n  --ci\n  --json\n'),
    };
    const shipped = citationProblems('docker exec <sandbox-container> npx hackmyagent scan --ci /app', cli);
    expect(shipped).toEqual([
      expect.stringContaining('--ci is not an option of `scan`'),
      expect.stringContaining('`scan` does not take a directory'),
    ]);
    expect(citationProblems('docker exec <sandbox-container> npx hackmyagent secure --ci /app', cli)).toEqual([]);
    expect(citationProblems('npx hackmyagent bogus-verb .', cli)).toEqual([
      expect.stringContaining('`bogus-verb` is not a hackmyagent command'),
    ]);
  });

  it('finds the scanner strings that cite a hackmyagent command', () => {
    const cited = stringLiterals(readFileSync(SCANNER, 'utf8')).filter((l) => verbsIn(l.body).length > 0);
    // The HMA-NMC-040 message and fix at least. [] would pass every rule below.
    expect(cited.length, 'no scanner string cites a hackmyagent command').toBeGreaterThanOrEqual(2);
    expect(cited.some((l) => /--[a-z]/.test(l.body)), 'no cited command carries a flag').toBe(true);
  });
});

describe('every hackmyagent command the NemoClaw scanner prints runs', () => {
  // Both cases read the built CLI's `--help`; a checkout that has not built
  // fails here by name instead of reporting them skipped.
  beforeAll(assertDistFresh);

  it('each one names a top-level command, its own flags and a directory it can scan', () => {
    const cli = builtCli();
    expect(cli.verbs.has('secure')).toBe(true);
    const src = readFileSync(SCANNER, 'utf8');
    const lineOf = (offset: number) => src.slice(0, offset).split('\n').length;
    const dead = stringLiterals(src)
      .flatMap((l) => citationProblems(l.body, cli).map((p) => `src/hardening/nemoclaw-scanner.ts:${lineOf(l.start)} ${p}`));
    expect(
      dead,
      'a NemoClaw finding prints a hackmyagent command that does not run as printed. '
      + 'Fix the string to name a command, flags and argument the CLI accepts.\n  - '
      + dead.join('\n  - '),
    ).toEqual([]);
  });

  it('HMA-NMC-040 as emitted: its fix runs, and its message names the command its fix runs', async () => {
    const findings = await scanFindings();
    const nmc040 = findings.find((f) => f.checkId === 'HMA-NMC-040');
    expect(nmc040, 'the scanner did not emit HMA-NMC-040 for a HOME holding ~/.nemoclaw').toBeDefined();
    expect(citationProblems(nmc040!.fix ?? '', builtCli())).toEqual([]);
    expect(verbsIn(nmc040!.fix ?? '')).toEqual(['secure']);

    // Every emitted finding whose fix runs a hackmyagent command: the prose
    // around it names that command and no other.
    const withCommand = findings.filter((f) => verbsIn(f.fix ?? '').length > 0);
    expect(withCommand.map((f) => f.checkId)).toContain('HMA-NMC-040');
    for (const f of withCommand) {
      const fixVerbs = verbsIn(f.fix ?? '');
      for (const named of verbsIn(`${f.message ?? ''}\n${f.description ?? ''}`)) {
        expect(fixVerbs, `${f.checkId} message names \`hackmyagent ${named}\`, its fix runs ${fixVerbs.join(', ')}`).toContain(named);
      }
    }
  });
});
