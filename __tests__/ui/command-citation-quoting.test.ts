// Commands built as DATA quote their operands (#273).
//
// These four helpers do not print. They build a command string and return it,
// and `src/cli.ts` renders it much later — so the source gate in
// `__tests__/helpers/render-source.ts`, which walks arguments to `console.log`
// and follows taint one level inside a single file, never saw them. It was
// green while sixteen sites across six files were live. Measured on `6a5c1db`,
// scanning a tree containing `.claude/skills/my skill$(id)/SKILL.md`:
//
//     Verify: hackmyagent secure .claude/skills/my skill$(id)
//
// The space retargets the command at a path that does not exist, and `$(id)`
// runs when the line is pasted.
//
// The property is asked of a real shell rather than of the emitted spelling.
// Comparing against `citationPath(target)` would be comparing the
// implementation with itself, and would have agreed with the bug; running the
// fragment through `sh`, `bash` and `zsh` asks the only question that matters —
// how many words does the reader's shell see, and is the one it resolves the
// file the report is about. zsh is included because it is the default shell on
// macOS and expands things `sh` does not (#340: a leading `=`).
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { soulScopeDisclosureLines } from '../../src/ui/soul-scope-disclosure';
import { quickScanScopeDisclosure, quickScanFollowupText } from '../../src/ui/quick-scan-labels';
import { citationPaths, commandNaming } from '../../src/ui/shell-quote';

/** Shells a reader might actually paste into, that exist on this machine. */
const SHELLS = ['sh', 'bash', 'zsh'].filter((sh) => {
  try {
    execFileSync('command', ['-v', sh], { stdio: 'ignore', shell: '/bin/sh' });
    return true;
  } catch {
    return false;
  }
});

it('exercised at least one real shell', () => {
  // Non-vacuity. Every assertion below loops over SHELLS, and an empty list
  // passes all of them without running anything.
  expect(SHELLS.length).toBeGreaterThan(0);
});

/** The words a shell sees in `fragment`. */
function shellWords(fragment: string, shell: string): string[] {
  return execFileSync(shell, ['-c', `printf '%s\\n' ${fragment}`], {
    encoding: 'utf8',
    timeout: 30_000,
  })
    .split('\n')
    .filter((w) => w !== '');
}

/**
 * `fragment` is exactly one argument to every shell, and it names `expected`.
 *
 * `./x` and `x` name the same file, and the `./` is deliberate (#340) so a path
 * starting with `-` is an operand rather than a flag — so it is stripped before
 * comparing. The assertion is about WHICH FILE the shell reaches.
 */
function expectOneArgumentNaming(fragment: string, expected: string, label: string): void {
  for (const shell of SHELLS) {
    let words: string[];
    try {
      words = shellWords(fragment, shell);
    } catch {
      throw new Error(`${label} [${shell}]: could not parse the emitted citation: ${fragment}`);
    }
    expect(words.length, `${label} [${shell}]: ${JSON.stringify(fragment)} is not one argument`).toBe(1);
    const named = words[0].startsWith('./') ? words[0].slice(2) : words[0];
    expect(named, `${label} [${shell}]: resolves to a different file`).toBe(expected);
  }
}

// A space (splits the command), a `$(…)` (runs on paste), and a `;` (starts a
// second command). All three are legal in a directory name on every filesystem
// this tool supports.
const HOSTILE = "my proj$(echo INJECTED); touch PWNED";

describe('soulScopeDisclosureLines quotes its target (#273)', () => {
  const base = { missing: 3, upgraded: 0, prefix: 'hackmyagent', directory: HOSTILE };

  it('quotes the --deep pointer on a keyword-only scan', () => {
    const [line] = soulScopeDisclosureLines({ ...base, deep: false, deepAvailable: false });
    const m = /scan-soul (.+) --deep$/.exec(line);
    expect(m, `no scan-soul citation in: ${line}`).not.toBeNull();
    expectOneArgumentNaming(m![1], HOSTILE, 'scan-soul --deep pointer');
  });

  it('quotes the harden-soul pointer after a semantic pass', () => {
    const lines = soulScopeDisclosureLines({ ...base, deep: true, deepAvailable: true });
    const line = lines.find((l) => l.includes('harden-soul'))!;
    const m = /harden-soul (.+)\.$/.exec(line);
    expect(m, `no harden-soul citation in: ${line}`).not.toBeNull();
    expectOneArgumentNaming(m![1], HOSTILE, 'harden-soul pointer');
  });
});

describe('quick-scan labels quote their target (#273)', () => {
  it('quotes the clean-verdict follow-up', () => {
    const { cleanVerdict } = quickScanScopeDisclosure({
      staticCount: 310,
      semanticCount: 1,
      fullAuditTarget: HOSTILE,
    });
    const m = /run `secure (.+)` before/.exec(cleanVerdict);
    expect(m, `no secure citation in: ${cleanVerdict}`).not.toBeNull();
    expectOneArgumentNaming(m![1], HOSTILE, 'quick-scan clean verdict');
  });

  it('quotes the follow-up CTA', () => {
    const text = quickScanFollowupText({ fullAuditTarget: HOSTILE });
    const m = /Run `secure (.+)` for the full audit/.exec(text);
    expect(m, `no secure citation in: ${text}`).not.toBeNull();
    expectOneArgumentNaming(m![1], HOSTILE, 'quick-scan follow-up');
  });
});

describe('the citation primitives (#273)', () => {
  it('commandNaming builds a quoted command', () => {
    const cmd = commandNaming(HOSTILE, (p) => `rm ${p}`);
    expect(cmd).toBeDefined();
    expectOneArgumentNaming(cmd!.slice('rm '.length), HOSTILE, 'commandNaming');
  });

  // The rule from shell-quote.ts: a path that cannot be SHOWN truthfully gets no
  // command at all, rather than a command naming bytes the reader cannot see.
  it('commandNaming yields no command for a path with a display hazard', () => {
    expect(commandNaming('nl\nsecond', (p) => `rm ${p}`)).toBeUndefined();
    expect(commandNaming('esc[2Jcleared', (p) => `rm ${p}`)).toBeUndefined();
  });

  it('citationPaths quotes every operand', () => {
    const cited = citationPaths(['a b.json', "it's.json"]);
    expect(cited).not.toBeNull();
    for (const shell of SHELLS) {
      expect(shellWords(cited!, shell)).toEqual(['a b.json', "it's.json"]);
    }
  });

  // All-or-nothing: a chmod that silently dropped one file would report a
  // remedy it did not offer, and the command looks complete either way.
  it('citationPaths refuses the whole list when any operand is unnameable', () => {
    expect(citationPaths(['fine.json', 'nl\nsecond'])).toBeNull();
  });
});
