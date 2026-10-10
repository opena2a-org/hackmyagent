/**
 * The README is the front door: a visitor decides from the first screen
 * whether the tool does the job they came for.
 *
 * Shadow AI detection (`detect`) is one of the primary jobs, and the README
 * first named it at line 233, inside the command reference. The one-line
 * description listed neither it nor governance grading, the Quick start showed
 * `secure` only, the file ran 527 lines against the 400-line budget for a CLI
 * README, there was no section saying how a scan works, and `--version` printed
 * `Telemetry: on` while the README never used the word. Each rule below holds
 * one of those as structure, so a later edit cannot quietly undo it.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');
const README = readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const LINES = README.split('\n');
const LINE_COUNT = README.endsWith('\n') ? LINES.length - 1 : LINES.length;

/** 1-based line number of the first line matching `pattern`, or Infinity. */
function firstLine(pattern: RegExp): number {
  const i = LINES.findIndex((l) => pattern.test(l));
  return i === -1 ? Infinity : i + 1;
}

/** The body of a `## ` section, up to the next `## ` heading. */
function section(heading: string): string {
  const start = README.indexOf(`\n${heading}\n`);
  expect(start, `${heading} was not found`).toBeGreaterThan(-1);
  const rest = README.slice(start + heading.length + 2);
  const end = rest.search(/\n## /);
  return end === -1 ? rest : rest.slice(0, end);
}

/** Fenced blocks in order, each with its info string and body. */
function fences(text: string): { info: string; body: string }[] {
  return [...text.matchAll(/```([^\n]*)\n([\s\S]*?)```/g)].map((m) => ({ info: m[1].trim(), body: m[2] }));
}

/** The output block that directly follows the shell block running `command`. */
function outputAfter(blocks: { info: string; body: string }[], command: string): string | undefined {
  const at = blocks.findIndex((b) => b.info === 'bash' && b.body.trim() === command);
  if (at === -1 || at + 1 >= blocks.length) return undefined;
  const next = blocks[at + 1];
  return next.info === '' ? next.body : undefined;
}

describe('README front door', () => {
  it('the one-line description under the title names shadow AI', () => {
    // The first prose line: not the title, a badge, the OpenA2A nav quote or a blank.
    const at = LINES.findIndex((l) => /^[A-Za-z]/.test(l));
    expect(at, 'no description line').toBeGreaterThan(-1);
    expect(at + 1, 'the description sits below the first section').toBeLessThan(firstLine(/^## /));
    expect(LINES[at]).toMatch(/shadow AI/);
  });

  it('names shadow AI within the first 30 lines', () => {
    expect(firstLine(/shadow ai/i)).toBeLessThan(30);
  });

  it('stays under the 400-line budget for a CLI README', () => {
    expect(LINE_COUNT).toBeLessThan(400);
  });

  it('shows the first command and the start of its output within the first 30 lines', () => {
    // 0-based indices: the command block opens, closes, then the output block opens.
    const quickStart = LINES.indexOf('## Quick start');
    const commandOpens = LINES.findIndex((l, i) => i > quickStart && l === '```bash');
    const commandCloses = LINES.findIndex((l, i) => i > commandOpens && l === '```');
    const outputOpens = LINES.findIndex((l, i) => i > commandCloses && l.startsWith('```'));
    expect(quickStart).toBeGreaterThan(-1);
    expect(commandOpens).toBeGreaterThan(quickStart);
    expect(LINES[outputOpens], 'the block after the first command is not an output block').toBe('```');
    expect(outputOpens + 1).toBeLessThan(30);
  });

  it('Quick start runs secure and detect, each followed by its captured output', () => {
    const blocks = fences(section('## Quick start'));
    const secure = outputAfter(blocks, 'npx hackmyagent secure');
    const detect = outputAfter(blocks, 'npx hackmyagent detect');
    expect(secure, 'no output block after `npx hackmyagent secure`').toBeDefined();
    expect(detect, 'no output block after `npx hackmyagent detect`').toBeDefined();
    expect(secure!).toMatch(/files analyzed/);
    expect(secure!).toMatch(/── Findings/);
    expect(detect!).toMatch(/shadow ai audit/);
    expect(detect!).toMatch(/── Shadow AI agents/);
  });

  it('Quick start says when the captures were taken and from which version', () => {
    const quickStart = section('## Quick start');
    expect(quickStart).toMatch(/\b20\d\d-\d\d-\d\d\b/);
    expect(quickStart).toMatch(/hackmyagent \d+\.\d+\.\d+/);
  });

  it('has exactly one How it works section', () => {
    expect(README.match(/^## How it works$/gm) ?? []).toHaveLength(1);
  });

  it('has a Telemetry section naming what --version prints and the opt-out the CLI help names', () => {
    const telemetry = section('## Telemetry');
    expect(telemetry).toMatch(/`Telemetry: on/);
    // The variable the CLI's own --help text tells a user to set.
    const cli = readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf8');
    const optOut = /Usage telemetry is on[^\n]*Disable: (\S+)/.exec(cli);
    expect(optOut, 'src/cli.ts no longer states the usage-telemetry opt-out').not.toBeNull();
    expect(telemetry).toContain(optOut![1]);
    expect(telemetry).toContain('hackmyagent telemetry off');
  });
});
