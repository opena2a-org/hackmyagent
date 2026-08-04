/**
 * #191 — HMA_CLI_PREFIX is honored natively in user-facing command citations.
 *
 * opena2a-cli bundles hackmyagent and sets HMA_CLI_PREFIX=opena2a so spawned
 * `hackmyagent` output cites the parent CLI's verb namespace. This gate asserts:
 *   - With HMA_CLI_PREFIX set, `--help` Usage lines and example blocks render
 *     the prefix and leak ZERO `hackmyagent <verb>` command citations.
 *   - With it UNSET, the same surfaces render `hackmyagent …` (regression guard
 *     for standalone users — behavior must be identical to before).
 *   - rebrandCommandCitations rewrites verb pairs but never the bare package
 *     name, install commands, paths, URLs, or MCP tool ids.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { rebrandCommandCitations, resolveCliPrefix } from '../src/cli-prefix';
import { assertDistFreshIfPresent } from './helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..');
const CLI_PATH = path.join(REPO_ROOT, 'dist', 'cli.js');

// Any `hackmyagent <verb>` pair where <verb> is a real subcommand a user would
// type. Bare `hackmyagent` (URLs, install cmds, paths, the `_` MCP ids) must
// NOT match, so the right side requires whitespace + a lowercase verb char.
const LEAKED_CITATION = /(?:^|[\s`(])(?:npx )?hackmyagent\s+[a-z]/;

function helpOutput(command: string, withPrefix: boolean): string {
  const env = { ...process.env };
  if (withPrefix) env.HMA_CLI_PREFIX = 'opena2a';
  else delete env.HMA_CLI_PREFIX;
  // Strip ANSI so the regex sees raw text.
  const raw = execFileSync('node', [CLI_PATH, ...command.split(' '), '--help'], {
    env,
    encoding: 'utf8',
  });
  // eslint-disable-next-line no-control-regex
  return raw.replace(/\x1b\[[0-9;]*m/g, '');
}

describe('rebrandCommandCitations (pure)', () => {
  it('is a no-op when the prefix is the default hackmyagent', () => {
    // resolveCliPrefix() returns hackmyagent under the test argv0, so the
    // module-level CLI_PREFIX is hackmyagent and rebrand returns input verbatim.
    delete process.env.HMA_CLI_PREFIX;
    expect(rebrandCommandCitations('Run hackmyagent secure --fix')).toBe(
      'Run hackmyagent secure --fix',
    );
  });
});

describe('resolveCliPrefix', () => {
  it('returns the HMA_CLI_PREFIX env value verbatim when set', () => {
    const prev = process.env.HMA_CLI_PREFIX;
    process.env.HMA_CLI_PREFIX = 'opena2a';
    expect(resolveCliPrefix()).toBe('opena2a');
    if (prev === undefined) delete process.env.HMA_CLI_PREFIX;
    else process.env.HMA_CLI_PREFIX = prev;
  });

  it('defaults to hackmyagent when unset and not invoked as opena2a', () => {
    const prev = process.env.HMA_CLI_PREFIX;
    delete process.env.HMA_CLI_PREFIX;
    expect(resolveCliPrefix()).toBe('hackmyagent');
    if (prev !== undefined) process.env.HMA_CLI_PREFIX = prev;
  });
});

// The spawned-help assertions need the built CLI. Mirror the sibling
// command-reference test: guard on dist existence so the suite fails loudly
// with a build hint rather than a cryptic ENOENT.
describe('--help command citations honor HMA_CLI_PREFIX (#191)', () => {
  it('dist/cli.js exists (run `npm run build` if missing)', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  for (const cmd of ['secure', 'check', 'attack', 'scan-soul']) {
    it(`\`${cmd} --help\` renders opena2a and leaks no hackmyagent citation when prefixed`, () => {
      if (!existsSync(CLI_PATH)) return;
      const out = helpOutput(cmd, true);
      expect(out).toMatch(/Usage:\s+opena2a /);
      expect(out).not.toMatch(LEAKED_CITATION);
    });
  }

  it('top-level --help example block renders opena2a when prefixed', () => {
    if (!existsSync(CLI_PATH)) return;
    const out = helpOutput('', true);
    expect(out).toMatch(/opena2a (check|secure)/);
    expect(out).not.toMatch(LEAKED_CITATION);
  });

  it('`secure --help` still renders hackmyagent when the prefix is unset', () => {
    if (!existsSync(CLI_PATH)) return;
    const out = helpOutput('secure', false);
    expect(out).toMatch(/Usage:\s+hackmyagent secure/);
    expect(out).toMatch(/\$ hackmyagent secure/);
  });
});
