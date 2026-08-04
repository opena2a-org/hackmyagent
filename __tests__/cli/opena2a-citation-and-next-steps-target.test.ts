// Dead-end citation gates for the sibling-CLI verbs and the Next Steps
// target (closes #201 and #261).
//
// #201 — ~29 finding-fix and explainer strings cite `opena2a protect .`.
// A user who ran `npm i hackmyagent` standalone does not have `opena2a`
// on PATH, so the Fix line was `command not found`: a dead end under
// CISO Rule 11. Worse, the one-time install hint that existed to soften
// this said `npm i -g opena2a` — an unpublished name that 404s. The
// package is `opena2a-cli`; the binary it installs is `opena2a`.
//
// #261 — the Next Steps builder picked the directory to cite with
// `target.includes('.')` as a "this is a file" test. Every relative path
// contains a dot from its `./` prefix, so `./fixture/myagent` was
// dirname()'d to `./fixture` — the PARENT of the scanned directory —
// while `check` on the same block cited the correct path. Following the
// suggestion acted on the wrong tree.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, cpSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  rebrandCommandCitations,
  OPENA2A_PACKAGE,
  CLI_PREFIX,
} from '../../src/cli-prefix';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

function canRunSpawn(): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  return existsSync(CLI);
}

describe('sibling-CLI citations are runnable standalone (#201)', () => {
  // The suite runs the module standalone, so CLI_PREFIX is the default and
  // the opena2a rewrite is active. Assert that precondition rather than
  // silently passing if the environment ever changes.
  it('runs with the default prefix, so the rewrite is in effect', () => {
    expect(CLI_PREFIX).toBe('hackmyagent');
  });

  it('names a package that actually exists on npm', () => {
    // `npm i -g opena2a` is a 404. This is the published name.
    expect(OPENA2A_PACKAGE).toBe('opena2a-cli');
  });

  it('rewrites `opena2a protect` to a self-installing invocation', () => {
    const fix = 'Hardcoded credential. Run: opena2a protect .  — vaults the secret.';
    expect(rebrandCommandCitations(fix)).toContain('npx opena2a-cli protect .');
    // The bare form must not survive — that is the dead end.
    expect(rebrandCommandCitations(fix)).not.toMatch(/(?<!-cli )opena2a protect/);
  });

  it('rewrites `opena2a mcp` too', () => {
    expect(rebrandCommandCitations('Run: opena2a mcp audit')).toContain(
      'npx opena2a-cli mcp audit',
    );
  });

  it('is idempotent — a rewritten string does not accumulate npx prefixes', () => {
    const once = rebrandCommandCitations('Run: opena2a protect .');
    expect(rebrandCommandCitations(once)).toBe(once);
  });

  it('leaves prose mentions of the CLI alone', () => {
    // Verb-anchored: these have no recognized verb after the name, so the
    // pattern must not touch them.
    const prose = 'opena2a is a separate CLI, and opena2a or hackmyagent can redirect.';
    expect(rebrandCommandCitations(prose)).toBe(prose);
  });

  it('does not match the name embedded in a scoped package or path', () => {
    const embedded = '@opena2a/cli-ui and node_modules/opena2a-cli/dist';
    expect(rebrandCommandCitations(embedded)).toBe(embedded);
  });
});

// The dirTarget-bearing Next Steps entries (harden-soul / protect) only
// render when the scan produced governance or credential findings, so a
// minimal hand-rolled fixture leaves the assertions vacuous. The corpus
// kitchen-sink repo fires both. Gate on its presence rather than assert
// against a fixture that cannot exercise the code path.
const CORPUS_KITCHEN_SINK = join(
  process.env.HOME || '',
  '.opena2a',
  'corpus',
  'repo',
  'malicious',
  'kitchen-sink',
);

function canRunNextSteps(): boolean {
  return canRunSpawn() && existsSync(CORPUS_KITCHEN_SINK);
}

describe('Next Steps cites the scanned directory, not its parent (#261)', { timeout: 300_000 }, () => {
  it.runIf(canRunNextSteps())('a nested agent dir is cited as itself', () => {
    const root = mkdtempSync(join(tmpdir(), 'hma-261-'));
    try {
      const wrapper = join(root, 'fixture');
      mkdirSync(wrapper, { recursive: true });
      cpSync(CORPUS_KITCHEN_SINK, join(wrapper, 'myagent'), { recursive: true });

      const res = spawnSync('node', [CLI, 'secure', './fixture/myagent'], {
        cwd: root,
        encoding: 'utf8',
        timeout: 240_000,
      });

      const stdout = res.stdout || '';
      const nextSteps = stdout.slice(stdout.indexOf('Next Steps'));

      // Guard against a vacuous pass: the entries under test must be present.
      expect(nextSteps).toMatch(/harden-soul/);
      expect(nextSteps).toMatch(/protect/);

      // The wrapper dir must never be the cited target. Pre-fix, both
      // entries pointed at `./fixture` — the PARENT of the scanned dir —
      // because `'./fixture/myagent'.includes('.')` was read as "is a file".
      expect(nextSteps).not.toMatch(/(?:harden-soul|protect)\s+\.\/fixture(?!\/myagent)/);
      // And they must cite the directory actually scanned.
      expect(nextSteps).toMatch(/harden-soul\s+\.\/fixture\/myagent/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.runIf(canRunNextSteps())('a directory whose name contains a dot is not truncated', () => {
    // The `includes('.')` heuristic also mangled legitimately dotted
    // directory names, independent of the `./` prefix bug: dirname of
    // 'my.project' is '.', silently retargeting the suggested command at
    // the whole working tree instead of the scanned directory.
    const root = mkdtempSync(join(tmpdir(), 'hma-261-dot-'));
    try {
      cpSync(CORPUS_KITCHEN_SINK, join(root, 'my.project'), { recursive: true });

      // `./`-prefixed: the Next Steps entries under test only render for a
      // target recognized as local (a `.` / `/` / `~` prefix), and this form
      // is also what a user actually types.
      const res = spawnSync('node', [CLI, 'secure', './my.project'], {
        cwd: root,
        encoding: 'utf8',
        timeout: 240_000,
      });

      const stdout = res.stdout || '';
      const nextSteps = stdout.slice(stdout.indexOf('Next Steps'));

      expect(nextSteps).toMatch(/harden-soul/);
      expect(nextSteps).toMatch(/harden-soul\s+\.\/my\.project/);
      // Pre-fix: dirname('./my.project') === '.', retargeting the command
      // at the working tree rather than the scanned directory.
      expect(nextSteps).not.toMatch(/harden-soul\s+\.(?:\s|$)/m);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
