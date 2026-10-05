/**
 * #273 — every command `scan-soul` prints names its target as ONE argument.
 *
 * `soulScopeDisclosureLines` quotes the directory it is handed, and its unit
 * test (`__tests__/ui/command-citation-quoting.test.ts`) hands it the raw
 * target, so that suite was green. `src/cli.ts` quoted the target as well
 * before handing it over, so the printed line was quoted twice:
 *
 *     Semantic pass: hackmyagent scan-soul ''\''my proj; touch PWNED'\''' --deep
 *
 * Twice-quoted, the `;` sits outside every quote, and pasting the line runs
 * the `touch`. The unit layer was right and the consumer was not, so this
 * suite asks the built CLI, the way the reader receives it, and asks real
 * shells how many words each printed target is.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

/** Shells a reader might actually paste into, that exist on this machine. */
const SHELLS = ['sh', 'bash', 'zsh'].filter((sh) => {
  try {
    execFileSync('command', ['-v', sh], { stdio: 'ignore', shell: '/bin/sh' });
    return true;
  } catch {
    return false;
  }
});

// A space (splits the command), a `$(…)` (runs on paste) and a `;` (starts a
// second command). All three are legal in a directory name.
const HOSTILE = 'my proj$(echo INJECTED); touch PWNED';

// No violation, several controls missing: the shape that prints the
// method-scope disclosure line as well as the harden-soul pointers.
const SOUL = ['# Soul', '', 'Be helpful.', ''].join('\n');

let root: string;
let sandbox: string;

beforeAll(() => {
  root = tempDir('hma-273-cli-');
  fs.mkdirSync(path.join(root, HOSTILE));
  fs.writeFileSync(path.join(root, HOSTILE, 'SOUL.md'), SOUL);
  // Where the shells parse the printed fragments. If a fragment is broken, the
  // command it smuggles runs here and nowhere near the repository.
  sandbox = tempDir('hma-273-sh-');
});

afterAll(() => {
  for (const d of [root, sandbox]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(args: string[]): string {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: root,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: tempDir('hma-home-'),
    },
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

/** The words a shell sees in `fragment`. */
function shellWords(fragment: string, shell: string): string[] {
  return execFileSync(shell, ['-c', `printf '%s\\n' ${fragment}`], {
    cwd: sandbox,
    encoding: 'utf8',
    timeout: 30_000,
  })
    .split('\n')
    .filter((w) => w !== '');
}

/** The target operand of every `scan-soul` / `harden-soul` command in `out`. */
function citedTargets(out: string): { line: string; fragment: string }[] {
  const found: { line: string; fragment: string }[] = [];
  for (const raw of out.split('\n')) {
    const line = raw.trimEnd();
    const re = /hackmyagent (?:scan-soul|harden-soul) (.+?)(?: --deep| --dry-run)?(?:`|$)/g;
    for (const m of line.matchAll(re)) found.push({ line, fragment: m[1] });
  }
  return found;
}

describe('#273 scan-soul prints every command with its target as one argument', () => {
  it('exercised at least one real shell', () => {
    // Non-vacuity: every assertion below loops over SHELLS.
    expect(SHELLS.length).toBeGreaterThan(0);
  });

  it('quotes the target exactly once, in the disclosure line and every pointer', () => {
    const out = run(['scan-soul', HOSTILE]);
    const cited = citedTargets(out);

    // Non-vacuity: the disclosure line this regression was in must be on
    // screen, alongside the harden-soul pointers.
    expect(
      cited.some((c) => c.line.includes('Semantic pass:')),
      `the method-scope disclosure line was not printed:\n${out}`,
    ).toBe(true);
    expect(cited.some((c) => c.line.includes('harden-soul'))).toBe(true);

    for (const { line, fragment } of cited) {
      for (const shell of SHELLS) {
        // `./x` and `x` name the same directory; the question is which one the shell reaches.
        const words = shellWords(fragment, shell).map((w) => (w.startsWith('./') ? w.slice(2) : w));
        expect(words,`[${shell}] ${JSON.stringify(line)} does not name the target as one argument`).toEqual([HOSTILE]);
      }
    }
    // Belt and braces: had any fragment smuggled a command, it ran in the sandbox.
    expect(fs.readdirSync(sandbox)).toEqual([]);
  });
});
