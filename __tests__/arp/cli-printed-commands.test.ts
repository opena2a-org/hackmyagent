/**
 * Every command line the ARP CLI prints must run as printed.
 *
 * Its help printed `arp-guard <command>` and its telemetry hints printed
 * `arp telemetry ...`. Neither name is a binary: the `arp-guard` package
 * declares no `bin`, hackmyagent's only `bin` is `hackmyagent`, and on macOS
 * `arp` is the system address-resolution tool. A reader who typed the help got
 * "command not found", or a different program's usage text.
 *
 * `src/arp/` is outside the printed-flag walk in
 * `__tests__/ui/printed-flag-citations.test.ts` because it is not a Commander
 * program, so this is the same per-command check against its own dispatch:
 * the command a line names is registered, the flags it prints are read by
 * that command, and the program it starts with is the one that was run.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { invocation } from '../../src/arp/cli/invocation';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { arpCliCitations, arpCliRegistry } from '../helpers/printed-flag-citations';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const ARP_CLI_SRC = path.join(REPO_ROOT, 'src', 'arp', 'cli', 'index.ts');
const ARP_CLI_DIST = path.join(REPO_ROOT, 'dist', 'arp', 'cli', 'index.js');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

describe('invocation(): the command line that reaches the ARP CLI', () => {
  const cwd = '/home/u/project';
  const env = { PATH: '/usr/local/bin:/usr/bin' };

  it('names the node script, relative to the working directory, when run as a script', () => {
    expect(invocation(['/usr/bin/node', `${cwd}/node_modules/hackmyagent/dist/arp/cli/index.js`], env, cwd))
      .toBe('node node_modules/hackmyagent/dist/arp/cli/index.js');
  });

  it('keeps the absolute path when the script is outside the working directory', () => {
    expect(invocation(['/usr/bin/node', '/opt/lib/hackmyagent/dist/arp/cli/index.js'], env, cwd))
      .toBe('node /opt/lib/hackmyagent/dist/arp/cli/index.js');
  });

  it('names a bin shim by its name when its directory is on PATH', () => {
    expect(invocation(['/usr/bin/node', '/usr/local/bin/some-arp-bin'], env, cwd)).toBe('some-arp-bin');
  });

  it('names a bin shim by its full path when its directory is not on PATH', () => {
    expect(invocation(['/usr/bin/node', `${cwd}/node_modules/.bin/some-arp-bin`], env, cwd))
      .toBe(`${cwd}/node_modules/.bin/some-arp-bin`);
  });

  it('runs TypeScript source through tsx', () => {
    expect(invocation(['/usr/bin/node', `${cwd}/src/arp/cli/index.ts`], env, cwd))
      .toBe('npx tsx src/arp/cli/index.ts');
  });

  it('quotes a path the shell would split', () => {
    expect(invocation(['/usr/bin/node', '/Users/a b/dist/arp/cli/index.js'], env, cwd))
      .toBe("node '/Users/a b/dist/arp/cli/index.js'");
  });
});

describe('ARP CLI printed command lines name registered commands', () => {
  const src = readFileSync(ARP_CLI_SRC, 'utf8');
  const registry = arpCliRegistry(src);
  const citations = arpCliCitations(src);

  it('reads the dispatch (guards against a walk that finds nothing and passes)', () => {
    for (const verb of ['start', 'proxy', 'status', 'tail', 'budget', 'telemetry']) {
      expect(registry.verbs, verb).toContain(verb);
    }
    for (const sub of ['status', 'register', 'log', 'opt-out', 'opt-in', 'purge']) {
      expect(registry.telemetrySubs, sub).toContain(sub);
    }
    expect(registry.flags.get('start')).toContain('--config');
    expect(registry.flags.get('telemetry')).toContain('--no-purge');
    expect(citations.length).toBeGreaterThanOrEqual(10);
  });

  it('starts every printed command line with the invocation that was run', () => {
    const literal = citations
      .filter((c) => c.program !== '${PROG}' && registry.verbs.has(c.verb))
      .map((c) => `src/arp/cli/index.ts:${c.line} ${c.text}`);
    expect(literal, `printed with a program name that is not a binary:\n${literal.join('\n')}`).toEqual([]);
    expect(src).toMatch(/^const PROG = invocation\(\);$/m);
  });

  it('names only commands, subcommands and flags the program handles', () => {
    const dead: string[] = [];
    for (const c of citations.filter((x) => x.program === '${PROG}')) {
      const at = `src/arp/cli/index.ts:${c.line} ${c.text}`;
      if (!registry.verbs.has(c.verb)) { dead.push(`${at} -> unknown command '${c.verb}'`); continue; }
      if (c.verb === 'telemetry' && c.sub && !registry.telemetrySubs.has(c.sub)) {
        dead.push(`${at} -> unknown telemetry subcommand '${c.sub}'`);
      }
      for (const flag of c.flags) {
        if (!registry.flags.get(c.verb)?.has(flag)) dead.push(`${at} -> '${c.verb}' does not read ${flag}`);
      }
    }
    expect(dead, dead.join('\n')).toEqual([]);
  });

  it('catches a planted dead citation of each kind', () => {
    const plant = [
      'async function main() {',
      '  switch (command) {',
      "    case 'status':",
      '      await showStatus();',
      '      break;',
      "    case 'telemetry':",
      '      await telemetryCommand();',
      '  }',
      '}',
      'async function showStatus() {}',
      'async function telemetryCommand() {',
      "  switch (sub) { case 'log': break; }",
      '}',
      "console.log('Run: arp-guard status');",
      "console.log('Run: arp telemetry log');",
      'console.log(`Run: ${PROG} budget`);',
      'console.log(`Run: ${PROG} telemetry purge`);',
      'console.log(`Run: ${PROG} status --verbose   Show status`);',
      'console.log(`arp-guard v${VERSION}`);',
    ].join('\n');
    const reg = arpCliRegistry(plant);
    const found = arpCliCitations(plant);
    expect(found.filter((c) => c.program !== '${PROG}' && reg.verbs.has(c.verb)).map((c) => c.program))
      .toEqual(['arp-guard', 'arp']);
    const prog = found.filter((c) => c.program === '${PROG}');
    expect(prog.map((c) => [c.verb, c.sub, c.flags])).toEqual([
      ['budget', null, []],
      ['telemetry', 'purge', []],
      ['status', null, ['--verbose']],
    ]);
    expect(reg.verbs.has('budget')).toBe(false);
    expect(reg.telemetrySubs.has('purge')).toBe(false);
    expect(reg.flags.get('status')?.has('--verbose')).toBe(false);
  });
});

describe('ARP CLI help, rendered and run as printed', () => {
  /**
   * The built program when there is one, else the source through tsx. Not
   * skipped when neither exists: a skip would report a pass over a surface
   * nobody rendered.
   */
  function run(args: string[]): string {
    const useDist = existsSync(ARP_CLI_DIST);
    if (!useDist && !existsSync(TSX)) {
      throw new Error('Neither dist/arp/cli/index.js nor node_modules/.bin/tsx is present; run `npm ci` first.');
    }
    return execFileSync(useDist ? process.execPath : TSX, [useDist ? ARP_CLI_DIST : ARP_CLI_SRC, ...args], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    });
  }

  it('prints the invocation that was run, and the printed status line runs', () => {
    const help = run(['--help']);
    const usage = /USAGE\n\s+(.+) <command> \[options\]/.exec(help);
    expect(usage, help).not.toBeNull();
    const prog = usage![1];
    expect(prog).toBe(existsSync(ARP_CLI_DIST) ? 'node dist/arp/cli/index.js' : 'npx tsx src/arp/cli/index.ts');
    expect(help).not.toMatch(/\barp-guard [a-z]/);

    const examples = help.slice(help.indexOf('EXAMPLES')).split('\n').slice(1).filter((l) => l.trim());
    expect(examples.length).toBeGreaterThan(0);
    for (const line of examples) expect(line.trim().startsWith(`${prog} `), line).toBe(true);

    // The reader's next step: copy the printed status line into a shell.
    const statusLine = examples.map((l) => l.trim()).find((l) => l.startsWith(`${prog} status`))!;
    const command = statusLine.split(/ {2,}/)[0];
    const out = execFileSync('/bin/sh', ['-c', command], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    });
    expect(out).toContain('ARP Guard Status');
  });

  it('prints the same invocation in the telemetry help', () => {
    const help = run(['--help']);
    const prog = /USAGE\n\s+(.+) <command> \[options\]/.exec(help)![1];
    const telemetry = run(['telemetry', '--help']);
    expect(telemetry).toContain(`${prog} telemetry <subcommand>`);
    expect(telemetry).toContain(`review it with: ${prog} telemetry log`);
    expect(telemetry).not.toMatch(/(?<![\w./-])arp telemetry/);
  });
});
