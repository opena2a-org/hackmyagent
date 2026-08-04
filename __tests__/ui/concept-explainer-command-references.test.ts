/**
 * #163 — concept-explainer command cross-reference.
 *
 * Walks src/ui/concept-explainers.ts and asserts every cited
 * `hackmyagent <verb> [--flag]` parses via the live Commander program.
 *
 * Why this exists: PR #142 shipped a concept-explainer body citing
 * `scan-soul --explain`, which was never registered as a Commander option
 * — every credential-finding scan that triggered the SOUL-governance
 * explainer pointed users at a dead-end command. This test gates the
 * registry so a future explainer can never cite a non-existent command.
 *
 * Scope is intentionally narrow: only the concept-explainer registry.
 * Broader cross-reference of finding-fix strings (`fix:` / `audit:` /
 * docstring `Usage:` blocks) is tracked separately — see follow-up
 * issue. Adding those here would entangle this gate with pre-existing
 * stale-string drift in oasb-1.ts / asff.ts / opt-in.ts that predates
 * #163.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '../..');
const CLI_PATH = path.join(REPO_ROOT, 'dist', 'cli.js');
const EXPLAINERS_PATH = path.join(REPO_ROOT, 'src', 'ui', 'concept-explainers.ts');

interface CitedRef {
  verb: string;
  flags: string[];
  source: string;
}

function extractRefs(content: string, file: string, knownVerbs: ReadonlySet<string>): CitedRef[] {
  // Match either `hackmyagent <verb>` (case-sensitive — prose like
  // "Run HackMyAgent as an MCP server" is not a CLI invocation) OR a
  // bare reference `<known-verb>` where `<known-verb>` is one of the
  // commands registered in the live Commander program. The bare-verb
  // form catches concept-explainer copy like "Run `scan-soul --explain`".
  const refs: CitedRef[] = [];
  const lines = content.split('\n');
  const matchesAround = (line: string, start: number, end: number): string => {
    // `start`/`end` are the verb's index range on `line`. Return the
    // window from after the verb up to a flag-terminating boundary so
    // unrelated commands later on the same line don't leak in.
    const rest = line.slice(end);
    const terminator = rest.search(/[`'"]|\s—\s|\.\s|$/);
    return terminator >= 0 ? rest.slice(0, terminator) : rest;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Form 1: explicit `hackmyagent <verb>` prefix.
    const explicitRe = /\bhackmyagent\s+([a-z][a-z0-9-]+)(?![a-z0-9-])/g;
    let m: RegExpExecArray | null;
    while ((m = explicitRe.exec(line)) !== null) {
      const verb = m[1];
      const window = matchesAround(line, m.index, m.index + m[0].length);
      refs.push({ verb, flags: extractFlags(window), source: `${path.relative(REPO_ROOT, file)}:${i + 1}` });
    }

    // Form 2: bare `<known-verb> --<flag>` inside backticks. We require
    // the `--<flag>` immediately after the verb to avoid capturing prose
    // mentions like "the scan-soul scanner" — only command-shaped citations
    // count.
    const bareRe = /`([a-z][a-z0-9-]+)(\s+--[a-z][a-z0-9- =<>"'/.]*)?`/g;
    while ((m = bareRe.exec(line)) !== null) {
      const verb = m[1];
      if (!knownVerbs.has(verb)) continue;
      const flagSegment = m[2] ?? '';
      const flags = extractFlags(flagSegment);
      // Skip if no flags AND we already captured this same line via
      // Form 1 (avoids double-counting the same citation).
      if (flags.length === 0) continue;
      if (refs.some((r) => r.verb === verb && r.source.endsWith(`:${i + 1}`) && r.flags.join(',') === flags.join(','))) continue;
      refs.push({ verb, flags, source: `${path.relative(REPO_ROOT, file)}:${i + 1}` });
    }
  }
  return refs;
}

function extractFlags(window: string): string[] {
  const flagRe = /(?:^|\s)(--[a-z][a-z0-9-]+)\b/g;
  const flags: string[] = [];
  let f: RegExpExecArray | null;
  while ((f = flagRe.exec(window)) !== null) {
    flags.push(f[1]);
  }
  return flags;
}

const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

function helpOutput(verb: string): string {
  // Spawn the CLI with `<verb> --help`. Commander prints help to stdout and
  // exits 0. If the verb is unknown, Commander prints to stderr and exits
  // non-zero — we surface the mismatch as a test failure.
  const out = execFileSync(process.execPath, [CLI_PATH, verb, '--help'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    timeout: 15000,
    env: { ...process.env, NODE_OPTIONS: '' },
  });
  return out.replace(STRIP_ANSI, '');
}

function loadKnownVerbs(): Set<string> {
  // Parse `<root> --help` Commander output and extract every subcommand
  // name (first whitespace-leading token in the "Commands:" block).
  const root = execFileSync(process.execPath, [CLI_PATH, '--help'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    timeout: 15000,
    env: { ...process.env, NODE_OPTIONS: '' },
  }).replace(STRIP_ANSI, '');

  const verbs = new Set<string>();
  const lines = root.split('\n');
  let inCommands = false;
  for (const line of lines) {
    if (/^Commands:/.test(line)) {
      inCommands = true;
      continue;
    }
    if (!inCommands) continue;
    const trimmed = line.trimStart();
    if (trimmed.length === 0) continue;
    if (line.length > 0 && !/^\s/.test(line)) break; // out of Commands block
    const match = /^([a-z][a-z0-9-]+)\b/.exec(trimmed);
    if (match) verbs.add(match[1]);
  }
  return verbs;
}

describe('concept-explainer command cross-reference (#163)', () => {
  it('dist/cli.js exists (run `npm run build` if missing)', () => {
    expect(existsSync(CLI_PATH), `${CLI_PATH} not found`).toBe(true);
  });

  it('every cited `hackmyagent <verb>` in concept-explainers.ts parses as a Commander command', () => {
    if (!existsSync(CLI_PATH)) return; // first test handles the messaging

    const knownVerbs = loadKnownVerbs();
    expect(knownVerbs.size, 'failed to extract any verbs from --help').toBeGreaterThan(5);

    const content = readFileSync(EXPLAINERS_PATH, 'utf8');
    const refs = extractRefs(content, EXPLAINERS_PATH, knownVerbs);
    expect(refs.length, 'extractor returned zero refs from concept-explainers.ts — regex broken?').toBeGreaterThan(0);

    const helpCache = new Map<string, string>();
    const failures: string[] = [];

    for (const ref of refs) {
      let help: string | undefined = helpCache.get(ref.verb);
      if (help === undefined) {
        try {
          help = helpOutput(ref.verb);
          helpCache.set(ref.verb, help);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          failures.push(`${ref.source}: \`hackmyagent ${ref.verb}\` is not a registered command (Commander rejected it). Underlying: ${msg.split('\n')[0]}`);
          continue;
        }
      }

      // Confirm the verb appears as a registered subcommand in the help
      // output. Commander's help line for a subcommand looks like
      //   "Usage: hackmyagent <verb> [options] [arguments]"
      const usageRe = new RegExp(`Usage:\\s+(?:hackmyagent|cli\\.js)\\s+${ref.verb}\\b`, 'm');
      if (!usageRe.test(help)) {
        failures.push(`${ref.source}: \`hackmyagent ${ref.verb}\` invoked but Commander help does not show a Usage line for it`);
      }

      for (const flag of ref.flags) {
        // Commander help shows option flags either inline (`--flag <value>`)
        // or aliased (`-x, --flag`). Match either.
        const flagRe = new RegExp(`(?:^|\\s)${flag.replace(/-/g, '\\-')}(?:\\s|,|$)`, 'm');
        if (!flagRe.test(help)) {
          failures.push(`${ref.source}: \`hackmyagent ${ref.verb} ${flag}\` cited but \`${flag}\` is not registered on \`${ref.verb}\``);
        }
      }
    }

    expect(failures, `Cross-ref failures:\n  - ${failures.join('\n  - ')}`).toEqual([]);
  });

  it('explicit regression: scan-soul --explain is wired (the reason this test exists)', () => {
    if (!existsSync(CLI_PATH)) return;
    const help = helpOutput('scan-soul');
    expect(help).toMatch(/--explain\b/);
  });
});
