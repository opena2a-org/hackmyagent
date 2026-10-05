/**
 * `detect` keeps a fix's command and its words in separate fields, and only
 * the command is styled to be copied.
 *
 * Two findings used to put words in `remediation`:
 *
 *   - "AI config files grant broad permissions" carried only words
 *     (`Narrow .claude/settings.json:2 — replace "Bash(*)" with ...`);
 *   - "AI config files contain credential references" carried a command with a
 *     sentence glued to it (`opena2a protect <dir>  — migrates hardcoded
 *     secrets ...`).
 *
 * Both rendered in the command colour on the Fix line and sat in the JSON field
 * a consumer pastes into a shell. Pasted words are not inert: the first word
 * runs as a program, an apostrophe leaves an unterminated quote, and a `>`
 * creates a file.
 *
 * WHAT THIS PINS:
 *   1. `remediation` in `--json` is a command or null, and the words are in
 *      `remediationNote`;
 *   2. in the terminal the command colour goes to the command alone; a fix that
 *      is words alone renders as body text and its Verify command takes the
 *      command colour;
 *   3. the plain-text Fix line ends at the command, so selecting it copies no
 *      prose.
 *
 * HERMETICITY: a planted `ps` supplies the agent row and HOME is the planted
 * bin directory, same as `detect-verify-safety.test.ts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { remedyLines, type Finding } from '../../src/scanner/detect';

/** Placeholder value. Shaped like the real thing, obviously not real. */
const FAKE_ANTHROPIC = ['sk', '-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE'].join('');

/**
 * A palette whose only visible codes are the command colour, `dim` and reset,
 * so a test can read which text is inside a command span.
 */
const MARKED = {
  bold: '', dim: '[D]', reset: '[/]', green: '', yellow: '', red: '', brightRed: '', cyan: '[C]', white: '',
};

/** Every run of text the renderer put in the command colour. */
function commandSpans(lines: readonly string[]): string[] {
  const spans: string[] = [];
  for (const line of lines) {
    for (const m of line.matchAll(/\[C\](.*?)\[\/\]/g)) spans.push(m[1]);
  }
  return spans;
}

describe('remedyLines: only a command takes the command colour', () => {
  it('a command with a note: the command alone is coloured, the note is its own body-text line', () => {
    const f: Pick<Finding, 'remediation' | 'remediationNote' | 'verify'> = {
      remediation: 'opena2a protect .',
      remediationNote: 'Migrates hardcoded secrets into the Secretless vault.',
      verify: "sed -n '1p' ./.cursorrules",
    };
    const lines = remedyLines(f, '|', MARKED);
    expect(commandSpans(lines)).toEqual(['Fix:', 'opena2a protect .']);
    expect(lines).toContain('  | Migrates hardcoded secrets into the Secretless vault.');
    // With a fix command present, Verify stays secondary.
    expect(lines).toContain("  | [D]Verify:[/] [D]sed -n '1p' ./.cursorrules[/]");
  });

  it('words alone: the words are body text and the Verify command is the copy target', () => {
    const f: Pick<Finding, 'remediation' | 'remediationNote' | 'verify'> = {
      remediation: null,
      remediationNote: 'Narrow .claude/settings.json:2 — replace "Bash(*)" with "Bash(npm test)"',
      verify: "sed -n '2p' ./.claude/settings.json",
    };
    const lines = remedyLines(f, '|', MARKED);
    expect(commandSpans(lines)).toEqual(['Fix:', "sed -n '2p' ./.claude/settings.json"]);
    expect(lines).toContain('  | [C]Fix:[/] Narrow .claude/settings.json:2 — replace "Bash(*)" with "Bash(npm test)"');
  });

  it('words alone with no Verify: nothing but the label is coloured', () => {
    const lines = remedyLines({ remediation: null, remediationNote: 'Remove the entry.' }, '|', MARKED);
    expect(commandSpans(lines)).toEqual(['Fix:']);
  });
});

let root: string;
let fakeBin: string;

function runDetect(dir: string, json: boolean): string {
  try {
    return execFileSync(process.execPath, [BUILT_CLI, 'detect', dir, '--ci', ...(json ? ['--json'] : [])], {
      encoding: 'utf8',
      timeout: 180_000,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, NO_COLOR: '1', HOME: fakeBin, PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ''}` },
    });
  } catch (e: unknown) {
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

function findingTitled(dir: string, title: string): Finding {
  const doc = JSON.parse(runDetect(dir, true)) as { findings: Finding[] };
  const f = doc.findings.find((x) => x.title === title);
  expect(f, `no "${title}" finding, so this case proves nothing`).toBeDefined();
  return f as Finding;
}

beforeAll(() => {
  assertDistFresh();
  root = mkdtempSync(path.join(tmpdir(), 'hma-fixsplit-'));

  // Broad permission, no credential: the fix is an edit to one entry.
  const perm = path.join(root, 'perm');
  mkdirSync(path.join(perm, '.claude'), { recursive: true });
  writeFileSync(path.join(perm, 'package.json'), '{"name":"a","version":"1.0.0"}\n');
  writeFileSync(path.join(perm, '.claude', 'settings.json'), '{\n  "permissions": { "allow": ["Bash(*)"] }\n}\n');

  // A credential in an AI config: the fix is a command with an explanation.
  const cred = path.join(root, 'cred');
  mkdirSync(cred, { recursive: true });
  writeFileSync(path.join(cred, 'package.json'), '{"name":"b","version":"1.0.0"}\n');
  writeFileSync(path.join(cred, '.cursorrules'), `api_key: ${FAKE_ANTHROPIC}\n`);

  fakeBin = mkdtempSync(path.join(tmpdir(), 'hma-fixsplit-bin-'));
  const ps = path.join(fakeBin, 'ps');
  writeFileSync(
    ps,
    '#!/bin/sh\n'
    + "printf '%s\\n' 'USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND'\n"
    + "printf '%s\\n' 'fixture 4242 0.0 0.0 4200 900 ?? S 1:00AM 0:00.10 /usr/local/bin/aider --yes'\n",
  );
  chmodSync(ps, 0o755);
}, 180_000);

afterAll(() => {
  for (const d of [root, fakeBin]) if (d) rmSync(d, { recursive: true, force: true });
});

describe('detect --json: remediation is a command or null', () => {
  it('a broad-permission finding has no command: remediation is null and the words are the note', () => {
    const f = findingTitled(path.join(root, 'perm'), 'AI config files grant broad permissions');
    expect(f.remediation).toBeNull();
    expect(f.remediationNote).toMatch(/^Narrow \.claude\/settings\.json:2 — replace "Bash\(\*\)"/);
    expect(f.verify).toMatch(/^sed -n '2p' /);
  });

  it('a credential finding carries the bare command; the explanation is the note', () => {
    const f = findingTitled(path.join(root, 'cred'), 'AI config files contain credential references');
    // The target is the only argument; the path may be the temp dir's realpath.
    expect(f.remediation).toMatch(/^opena2a protect \S*cred$/);
    expect(f.remediationNote).toMatch(/^Migrates hardcoded secrets into the Secretless vault/);
  });
});

describe('detect text: the Fix line holds the command and nothing after it', () => {
  it('the credential Fix line ends at the command and the note follows on its own line', () => {
    const lines = runDetect(path.join(root, 'cred'), false).split('\n');
    const at = lines.findIndex((l) => /Fix: opena2a protect /.test(l));
    expect(at, 'no protect Fix line in the report').toBeGreaterThanOrEqual(0);
    expect(lines[at]).toMatch(/Fix: opena2a protect \S*cred$/);
    expect(lines[at + 1]).toMatch(/Migrates hardcoded secrets into the Secretless vault/);
  });

  it('the broad-permission finding prints its words under Fix and its Verify command after them', () => {
    const lines = runDetect(path.join(root, 'perm'), false).split('\n');
    const at = lines.findIndex((l) => /Fix: Narrow \.claude\/settings\.json:2/.test(l));
    expect(at, 'no Narrow Fix line in the report').toBeGreaterThanOrEqual(0);
    expect(lines[at + 1]).toMatch(/Verify: sed -n '2p' /);
  });
});
