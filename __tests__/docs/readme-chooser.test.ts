/**
 * The README section "What do you want to check?" is rendered from
 * docs/chooser.json by scripts/chooser.mjs. The data file is the one source
 * for the choice wording, the command and the next command, so a surface that
 * renders it shows what the README shows.
 *
 * This suite holds:
 *
 *  - the section between the markers is the rendering of the data, and
 *    `--check` exits 1 on a section edited by hand, 2 on a missing marker;
 *  - the section sits right after Quick start, before What it finds and
 *    Usage, with each choice's command on the line that asks it;
 *  - every command the data names is one the built CLI lists in `--help`, with
 *    the operands its usage line accepts and options registered on that
 *    command.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import {
  END,
  commandLine,
  commands,
  locateSection,
  renderSection,
  validateChooser,
} from '../../scripts/chooser.mjs';

const ROOT = path.resolve(__dirname, '../..');
const SCRIPT = path.join(ROOT, 'scripts', 'chooser.mjs');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const DATA = JSON.parse(readFileSync(path.join(ROOT, 'docs', 'chooser.json'), 'utf8'));
const README = readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const LINES = README.split('\n');

const verbOf = (args: string): string => args.split(/\s+/)[0];

/** Run the script on a README copy holding `text`; the copy lives in a temporary directory. */
function runScript(mode: '--check' | '--write', text: string): { status: number | null; stdout: string; stderr: string; after: string } {
  const file = path.join(tempDir('hma-chooser-readme-'), 'README.md');
  writeFileSync(file, text);
  const run = spawnSync(process.execPath, [SCRIPT, mode, '--readme', file], { encoding: 'utf8' });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr, after: readFileSync(file, 'utf8') };
}

describe('docs/chooser.json', () => {
  it('is valid', () => {
    expect(validateChooser(DATA)).toEqual([]);
  });

  it('validation names a missing next command and a repeated id (non-vacuity)', () => {
    const broken = structuredClone(DATA);
    delete broken.options[0].next;
    broken.more[0].id = broken.options[1].id;
    const problems = validateChooser(broken);
    expect(problems).toContain('options[0].next: missing or not one line of text');
    expect(problems.some((p: string) => p.startsWith('more[0].id:') && p.includes('used twice'))).toBe(true);
  });

  it('offers the five common jobs first and keeps scan-soul, red-team and scan under More', () => {
    expect(DATA.options.map((o: { run: string }) => verbOf(o.run))).toEqual(['secure', 'check', 'attack', 'scan-text', 'detect']);
    expect(DATA.more.map((m: { run: string }) => verbOf(m.run))).toEqual(['scan-soul', 'red-team', 'scan']);
  });

  it('says red-team leaves running its payloads to the reader', () => {
    // A reader who picks red-team to test an artifact believes they tested it.
    const redTeam = DATA.more.find((m: { run: string }) => verbOf(m.run) === 'red-team');
    expect(redTeam.ask).toMatch(/to run yourself/);
    expect(redTeam.findingMeans).toMatch(/does not run them/);
  });
});

describe('README "What do you want to check?"', () => {
  it('is the rendering of docs/chooser.json', () => {
    const location = locateSection(README);
    expect(location.problem).toBeUndefined();
    expect(location.text, 'regenerate with node scripts/chooser.mjs --write').toBe(renderSection(DATA));
  });

  it('--check exits 0 on the README, 1 on a section edited by hand and 2 without its end marker', () => {
    expect(runScript('--check', README).status).toBe(0);

    const ownLine = `\`${commandLine(DATA, DATA.options[0].run)}\``;
    expect(README).toContain(ownLine);
    const edited = runScript('--check', README.replace(ownLine, '`npx hackmyagent red-team <file>`'));
    expect(edited.status).toBe(1);
    expect(edited.stdout).toMatch(/README\.md:\d+: the section differs from docs\/chooser\.json/);

    const unmarked = runScript('--check', README.replace(`${END}\n`, ''));
    expect(unmarked.status).toBe(2);
    expect(unmarked.stderr).toContain(`0 lines read "${END}"`);
  });

  it('--write puts a section edited by hand back to the rendering', () => {
    const ownLine = `\`${commandLine(DATA, DATA.options[0].run)}\``;
    const written = runScript('--write', README.replace(ownLine, '`npx hackmyagent red-team <file>`'));
    expect(written.status).toBe(0);
    expect(written.after).toBe(README);
  });

  it('sits right after Quick start, before What it finds and Usage', () => {
    const location = locateSection(README);
    const headingsBefore = LINES.slice(0, location.start).filter((l) => l.startsWith('## '));
    expect(headingsBefore[headingsBefore.length - 1]).toBe('## Quick start');
    expect(LINES[location.start + 1]).toBe(`## ${DATA.question}`);
    const headingsAfter = LINES.slice(location.end + 1).filter((l) => l.startsWith('## '));
    expect(headingsAfter[0]).toBe('## What it finds');
    expect(headingsAfter).toContain('## Usage');
  });

  it('shows each choice with its command on the same line', () => {
    const section = LINES.slice(locateSection(README).start, locateSection(README).end + 1);
    for (const entry of [...DATA.options, ...DATA.more]) {
      const command = `\`${commandLine(DATA, entry.run)}\``;
      const line = section.find((l) => l.includes(entry.ask));
      expect(line, `no line asks "${entry.ask}"`).toBeDefined();
      // Bold markup aside, the choice reads "<ask>: `<command>`".
      expect(line!.replace(/\*\*/g, ''), `"${entry.ask}" is not followed by ${command} on its line`).toContain(`${entry.ask}: ${command}`);
    }
  });
});

describe('every command docs/chooser.json names parses in the built CLI', () => {
  beforeAll(assertDistFresh);

  let home = '';
  const helpCache = new Map<string, string>();
  /** `hackmyagent [verb] --help`, run from the build in a temporary HOME. */
  function help(verb?: string): string {
    const key = verb ?? '';
    if (!helpCache.has(key)) {
      const argv = verb ? [CLI, verb, '--help'] : [CLI, '--help'];
      const out = execFileSync(process.execPath, argv, {
        encoding: 'utf8',
        env: { PATH: process.env.PATH ?? '', HOME: home, NO_COLOR: '1', CI: 'true' },
        timeout: 30_000,
      });
      helpCache.set(key, out);
    }
    return helpCache.get(key)!;
  }
  beforeAll(() => {
    home = tempDir('hma-chooser-home-');
  });

  /** Why `args` would not parse; empty when it does. */
  function parseProblems(args: string): string[] {
    const [verb, ...rest] = args.split(/\s+/);
    const escaped = verb.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // A command line in the root Commands block, not a wrapped line of a description.
    const listed = new RegExp(`^ {2}${escaped}(?: \\[options\\])?(?: [<[]\\S*)*(?: {2,}|$)`, 'm');
    if (!listed.test(help())) return [`${verb} is not a command hackmyagent --help lists`];

    const own = help(verb);
    const usage = new RegExp(`^Usage: \\S+ ${escaped} (.*)$`, 'm').exec(own);
    if (!usage) return [`hackmyagent ${verb} --help prints no usage line`];
    const operands = usage[1].split(/\s+/).filter((t) => t !== '[options]');
    const required = operands.filter((t) => t.startsWith('<')).length;
    const allowed = operands.some((t) => t.includes('...')) ? Infinity : operands.length;

    const block = /\nOptions:\n([\s\S]*?)(?:\n\n|$)/.exec(own);
    if (!block) return [`hackmyagent ${verb} --help prints no Options block`];
    const takes = new Map<string, 'none' | 'required' | 'optional'>();
    for (const m of block[1].matchAll(/^ {2}(?:(-[A-Za-z]), )?(--[a-z][a-z0-9-]*)(?: (<[^>]+>|\[[^\]]+\]))?/gm)) {
      const kind = m[3] === undefined ? 'none' : m[3].startsWith('<') ? 'required' : 'optional';
      takes.set(m[2], kind);
      if (m[1]) takes.set(m[1], kind);
    }

    const problems: string[] = [];
    let positionals = 0;
    for (let i = 0; i < rest.length; i++) {
      const token = rest[i];
      if (token === '-' || !token.startsWith('-')) {
        positionals++;
        continue;
      }
      const kind = takes.get(token);
      if (kind === undefined) problems.push(`${token} is not an option of ${verb}`);
      else if (kind === 'required') {
        if (i + 1 >= rest.length) problems.push(`${token} needs a value`);
        i++;
      } else if (kind === 'optional' && i + 1 < rest.length && !rest[i + 1].startsWith('-')) i++;
    }
    if (positionals < required) problems.push(`${verb} needs ${required} operand(s), the command gives ${positionals}`);
    if (positionals > allowed) problems.push(`${verb} takes at most ${allowed} operand(s), the command gives ${positionals}`);
    return problems;
  }

  it('the invocation runs this package', () => {
    const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    expect(DATA.invocation).toBe(`npx ${pkg.name}`);
    expect(pkg.bin[pkg.name]).toBe('dist/cli.js');
  });

  it('the parse check refuses an unknown command, an unknown option and a missing or extra operand (non-vacuity)', () => {
    expect(parseProblems('no-such-command')).toEqual(['no-such-command is not a command hackmyagent --help lists']);
    expect(parseProblems('secure --no-such-option')).toEqual(['--no-such-option is not an option of secure']);
    expect(parseProblems('check')).toEqual(['check needs 1 operand(s), the command gives 0']);
    expect(parseProblems('scan-text <file> <other>')).toEqual(['scan-text takes at most 1 operand(s), the command gives 2']);
  });

  for (const c of commands(DATA)) {
    it(`${c.at}: ${commandLine(DATA, c.args)}`, () => {
      expect(parseProblems(c.args)).toEqual([]);
    });
  }
});
