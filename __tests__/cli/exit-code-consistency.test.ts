/**
 * #505, part 4: exit codes that can be told apart.
 *
 * - A command line Commander cannot parse exited 1, the code a scan uses for
 *   a critical or high finding. It now exits EXIT_USAGE (64), and so does a
 *   bare `explain`, the custom form of Commander's missing-argument error.
 * - `scan-soul` and `fix-all` on a directory that does not exist exited 1,
 *   while `secure`, `check`, `scan-text` and `detect` exited 2 (not measured).
 *   All of them now exit 2.
 * - `explain` with an unknown check ID stays non-zero (1), and
 *   `fix-all --dry-run` gates exactly like `--scan-only`
 *   (fix-all-dry-run-gate-parity.test.ts holds that half on a fixture with
 *   findings; here it is held on a missing directory).
 *
 * Every temporary directory is made in a hook: `vitest list` runs describe
 * bodies and module scope but no hook, so one made there is never removed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { UsageExitCommand, USAGE_ERROR_CODES } from '../../src/cli-usage-exit';
import { EXIT_FAIL, EXIT_UNMEASURED, EXIT_USAGE } from '../../src/check/verdict';

describe('UsageExitCommand', () => {
  /** Parses `argv` with every exit turned into a throw, and returns the error. */
  function parseError(build: (program: UsageExitCommand) => void, argv: string[]) {
    const program = new UsageExitCommand();
    program.exitOverride();
    program.configureOutput({ writeErr: () => {}, writeOut: () => {} });
    build(program);
    try {
      program.parse(argv, { from: 'user' });
    } catch (e) {
      return e as { code: string; exitCode: number };
    }
    throw new Error(`parse of ${JSON.stringify(argv)} did not end in an error`);
  }

  it('EXIT_USAGE is apart from every scan verdict code', () => {
    expect(EXIT_USAGE).toBe(64);
    expect([0, EXIT_FAIL, EXIT_UNMEASURED, 3]).not.toContain(EXIT_USAGE);
  });

  it.each([
    ['an unknown option', (p: UsageExitCommand) => { p.command('scan').action(() => {}); }, ['scan', '--no-such-option'], 'commander.unknownOption'],
    ['an unknown command', (p: UsageExitCommand) => { p.command('scan').action(() => {}); }, ['no-such-command'], 'commander.unknownCommand'],
    ['a missing operand', (p: UsageExitCommand) => { p.command('check').argument('<target>').action(() => {}); }, ['check'], 'commander.missingArgument'],
    ['an option without its value', (p: UsageExitCommand) => { p.command('scan').option('--fail-below <n>').action(() => {}); }, ['scan', '--fail-below'], 'commander.optionMissingArgument'],
    ['an extra operand', (p: UsageExitCommand) => { p.command('scan').argument('[dir]').allowExcessArguments(false).action(() => {}); }, ['scan', 'a', 'b'], 'commander.excessArguments'],
    ['a missing mandatory option', (p: UsageExitCommand) => { p.command('scan').requiredOption('--target <t>').action(() => {}); }, ['scan'], 'commander.missingMandatoryOptionValue'],
  ])('%s exits EXIT_USAGE, in a subcommand made by .command()', (_what, build, argv, code) => {
    const err = parseError(build, argv);
    expect(err.code).toBe(code);
    expect(USAGE_ERROR_CODES.has(code)).toBe(true);
    expect(err.exitCode).toBe(EXIT_USAGE);
  });

  it('a nested sub-program built by .command() maps its parse errors too', () => {
    const err = parseError((p) => {
      p.command('nanomind').command('status').action(() => {});
    }, ['nanomind', 'status', '--no-such-option']);
    expect(err.code).toBe('commander.unknownOption');
    expect(err.exitCode).toBe(EXIT_USAGE);
  });

  it('an error that is not a parse error keeps its own exit code', () => {
    const program = new UsageExitCommand();
    program.exitOverride();
    program.configureOutput({ writeErr: () => {}, writeOut: () => {} });
    let caught: { code: string; exitCode: number } | undefined;
    try {
      program.error('something else', { code: 'hma.other', exitCode: 3 });
    } catch (e) {
      caught = e as { code: string; exitCode: number };
    }
    expect(caught).toMatchObject({ code: 'hma.other', exitCode: 3 });
  });

  it('--help and --version still exit 0', () => {
    for (const argv of [['--help'], ['--version']]) {
      const program = new UsageExitCommand();
      program.version('1.0.0').exitOverride();
      program.configureOutput({ writeErr: () => {}, writeOut: () => {} });
      let caught: { exitCode: number } | undefined;
      try {
        program.parse(argv, { from: 'user' });
      } catch (e) {
        caught = e as { exitCode: number };
      }
      expect(caught?.exitCode, argv.join(' ')).toBe(0);
    }
  });
});

describe('exit codes of the built CLI (spawn)', () => {
  let home = '';
  let missing = '';
  beforeAll(() => {
    assertDistFreshIfPresent();
    home = tempDir('hma-exit-consistency-home-');
    // A path under a directory this suite owns, which nothing creates.
    missing = path.join(tempDir('hma-exit-consistency-'), 'no-such-dir');
  });

  function run(args: string[]) {
    const res = spawnSync(process.execPath, [BUILT_CLI, ...args], {
      encoding: 'utf-8',
      timeout: 120_000,
      env: { ...process.env, NO_COLOR: '1', HOME: home, OPENA2A_HOME: home, OPENA2A_TELEMETRY: 'off' },
    });
    return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
  }

  it.each([
    [['secure', '--no-such-option'], /unknown option '--no-such-option'/],
    [['no-such-command'], /unknown command 'no-such-command'/],
    [['check'], /missing required argument/],
    [['secure', '.', '--fail-below'], /argument missing/],
  ])('%j is a usage error: exit 64, with the parser message and help hint', (args, message) => {
    const r = run(args);
    expect(r.status, r.stderr).toBe(EXIT_USAGE);
    expect(r.stderr).toMatch(message);
    expect(r.stderr).toMatch(/run with --help for usage/);
    expect(r.stdout).toBe('');
  });

  it('a bare explain is a usage error; an unknown id is refused with exit 1', () => {
    const bare = run(['explain']);
    expect(bare.status, bare.stderr).toBe(EXIT_USAGE);
    expect(bare.stderr).toMatch(/No check ID given/);
    const empty = run(['explain', '']);
    expect(empty.status, empty.stderr).toBe(EXIT_USAGE);
    expect(empty.stderr).toMatch(/Empty check ID/);
    const unknown = run(['explain', 'NOPE-999']);
    expect(unknown.status, unknown.stderr).toBe(EXIT_FAIL);
    expect(unknown.stderr).toMatch(/Unknown check ID: NOPE-999/);
  });

  it('every scanning command exits 2 on a directory that does not exist', () => {
    const cases: string[][] = [
      ['secure', missing],
      ['check', missing],
      ['scan-text', missing],
      ['detect', missing],
      ['scan-soul', missing],
      ['scan-soul', missing, '--json'],
      ['fix-all', missing],
      ['fix-all', missing, '--dry-run'],
      ['fix-all', missing, '--scan-only'],
      ['fix-all', missing, '--json'],
    ];
    const got = cases.map((args) => ({ args: args.join(' ').replace(missing, '<missing>'), status: run(args).status }));
    expect(got).toEqual(cases.map((args) => ({ args: args.join(' ').replace(missing, '<missing>'), status: EXIT_UNMEASURED })));
  });

  it('--help and --version still exit 0', () => {
    expect(run(['--version']).status).toBe(0);
    expect(run(['secure', '--help']).status).toBe(0);
  });
});
