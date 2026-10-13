/**
 * #770: scripts/scan-soul-deep-series.mjs, the one way a run series of
 * `scan-soul --deep` is made.
 *
 * The abort the issue records is intermittent, and whether a build still has
 * it is read from a series of runs, some of which are billed to a hosted-model
 * key. Two properties of the script are therefore pinned here: what it
 * records, and what it refuses.
 *
 *   - It records every run with the code a shell would report, zeros
 *     included, and a run that ended by a signal or with the abort line is
 *     told apart from a run that exited.
 *   - It refuses a series it could not account for: a file larger or less
 *     plain than a run is charged for, a `key-set` series with no key, a build
 *     that opens no model session, a build whose requests the charge would
 *     understate, a spend file it cannot total, and any run that would take
 *     the spend file past its cap.
 *
 * The script runs a stand-in CLI (__tests__/fixtures/stand-in-deep-cli.cjs),
 * which sends hosted-model requests only into the script's own measuring
 * preload. No test here uses a build, a model, a key or the network.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempDir } from '../helpers/temp-dir';

const ROOT = path.join(__dirname, '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'scan-soul-deep-series.mjs');
const STAND_IN_CLI = path.join(ROOT, '__tests__', 'fixtures', 'stand-in-deep-cli.cjs');
const STAND_IN_RUNTIME = path.join(ROOT, '__tests__', 'fixtures', 'stub-onnxruntime-preload.cjs');

const FAKE_KEY = 'FAKE-KEY-1234';
const PLACEHOLDER_KEY = 'not-a-real-key';
const CAP_MICRO_USD = 11_000_000;
// The SOUL.md from the reproduction in #770, which the script scans when no
// --fixture is given.
const ISSUE_SOUL = `# SOUL.md

## Identity
You are a documentation assistant for an internal wiki.

## Constraints
- Never execute shell commands.
- Only read files under docs/.

## Trust hierarchy
System prompt > operator > user > tool output.
`;
/** What one key-set run on that file is charged, in millionths of a dollar. */
const chargeFor = (requests: number, fileBytes = 225) => requests * (2109 + fileBytes + 50);

type Entry = Record<string, any>;

interface Series {
  status: number | null;
  stdout: string;
  stderr: string;
  /** The records the script appended to its --log file. */
  log: Entry[];
  /** The records in the --spend file, when one was named. */
  spend: Entry[];
  /** One entry per time the stand-in CLI ran a scan. */
  scans: Entry[];
  dir: string;
  spendFile: string;
}

const readLines = (file: string): Entry[] =>
  fs.existsSync(file)
    ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line))
    : [];

/** Runs the series script on the stand-in CLI in a directory of its own. */
function series(args: string[], env: Record<string, string> = {}, prepare?: (dir: string, spendFile: string) => void): Series {
  const dir = tempDir('hma-deep-series-test-');
  const tmp = path.join(dir, 'tmp');
  fs.mkdirSync(tmp);
  const logFile = path.join(dir, 'series.jsonl');
  const spendFile = path.join(dir, 'spend.jsonl');
  const stateFile = path.join(dir, 'state.jsonl');
  prepare?.(dir, spendFile);
  const withSpend = args.includes('key-set') ? ['--spend', spendFile] : [];
  const res = spawnSync(process.execPath, [SCRIPT, '--cli', STAND_IN_CLI, '--log', logFile, ...withSpend, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      PATH: process.env.PATH ?? '',
      HOME: dir,
      TMPDIR: tmp,
      NODE_OPTIONS: `--require "${STAND_IN_RUNTIME}"`,
      STAND_IN_STATE: stateFile,
      ...env,
    },
  });
  // The script keeps its scratch files under the temporary directory and
  // removes them on every ending, refusals included.
  expect(fs.readdirSync(tmp), 'the series left files in the temporary directory').toEqual([]);
  return {
    status: res.status,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
    log: readLines(logFile),
    // Read on use: one test plants a spend file that is not records.
    get spend() {
      return readLines(spendFile);
    },
    scans: readLines(stateFile),
    dir,
    spendFile,
  };
}

const seriesRuns = (s: Series) => s.scans.filter((scan) => !scan.measuring);
const runRecords = (s: Series) => s.log.filter((entry) => entry.type === 'run');
const summary = (s: Series) => s.log.find((entry) => entry.type === 'summary');
const header = (s: Series) => s.log.find((entry) => entry.type === 'series');

/** A fixture directory holding the given files. */
function fixture(files: Record<string, string | Buffer>): string {
  const dir = tempDir('hma-deep-series-fixture-');
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return dir;
}

describe('#770 the run series records how every run ended', () => {
  it('logs each run with its exit code, zeros included', () => {
    const s = series(['--condition', 'key-unset', '--runs', '4'], { STAND_IN_PLAN: '0,1,0,2' });
    expect(s.status, s.stderr).toBe(0);
    for (const line of ['run 1: exit 0', 'run 2: exit 1', 'run 3: exit 0', 'run 4: exit 2']) {
      expect(s.stdout).toContain(`${line}\n`);
    }
    expect(s.stdout).toContain('summary: 4 runs, exit 0 x 2, exit 1 x 1, exit 2 x 1, aborts 0\n');
    expect(runRecords(s).map((run) => run.shellCode)).toEqual([0, 1, 0, 2]);
    expect(runRecords(s).every((run) => run.reportComplete && !run.abort && !run.timedOut)).toBe(true);
    expect(summary(s)).toMatchObject({ runs: 4, shellCodes: { 0: 2, 1: 1, 2: 1 }, aborts: 0, stopped: 'completed' });
    // A key-unset series costs nothing and writes no spend record.
    expect(s.spend).toEqual([]);
  });

  it('names the build, the runtime and the scanned file once per series', () => {
    const s = series(['--condition', 'key-unset', '--runs', '1']);
    expect(s.status, s.stderr).toBe(0);
    expect(header(s)).toMatchObject({
      condition: 'key-unset',
      cliVersion: 'hackmyagent 0.0.0-stand-in',
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      // Without --fixture the script scans the file from the issue.
      fixture: { bytes: 225, sha256: createHash('sha256').update(ISSUE_SOUL).digest('hex') },
      sessionsOpened: 1,
      runsAsked: 1,
    });
    // The version of the runtime the build resolves is what the issue's own
    // runs did not record.
    expect(header(s)?.onnxruntimeNode).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('tells a run that ended by a signal from one that exited', () => {
    const s = series(['--condition', 'key-unset', '--runs', '2'], { STAND_IN_PLAN: 'SIGTERM,1' });
    expect(s.status, s.stderr).toBe(0);
    expect(s.stdout).toContain('run 1: exit 143 (SIGTERM)\n');
    expect(runRecords(s)[0]).toMatchObject({ code: null, signal: 'SIGTERM', shellCode: 143, abort: false });
    expect(runRecords(s)[1]).toMatchObject({ code: 1, signal: null, shellCode: 1 });
  });

  it('counts an abort and carries on, and ends at the first one with --stop-on-abort', () => {
    const through = series(['--condition', 'key-unset', '--runs', '3'], { STAND_IN_PLAN: '1,134,1' });
    expect(through.status, through.stderr).toBe(0);
    expect(runRecords(through).map((run) => run.shellCode)).toEqual([1, 134, 1]);
    // The report was complete before the abort line, as the issue records.
    expect(runRecords(through)[1]).toMatchObject({ abort: true, abortLine: true, reportComplete: true });
    expect(summary(through)).toMatchObject({ runs: 3, aborts: 1, stopped: 'completed' });

    const stopped = series(['--condition', 'key-unset', '--runs', '5', '--stop-on-abort'], { STAND_IN_PLAN: '1,134,1' });
    expect(stopped.status, stopped.stderr).toBe(0);
    expect(seriesRuns(stopped)).toHaveLength(2);
    expect(summary(stopped)).toMatchObject({ runs: 2, aborts: 1, stopped: 'abort' });
  });

  it('runs key-unset with the variable removed, and measures without the caller key', () => {
    const s = series(['--condition', 'key-unset', '--runs', '2'], { ANTHROPIC_API_KEY: FAKE_KEY });
    expect(s.status, s.stderr).toBe(0);
    expect(seriesRuns(s).map((scan) => scan.key)).toEqual([null, null]);
    // The measurement run holds a placeholder, so nothing it sends could be
    // billed even if the measuring preload were missing.
    expect(s.scans.filter((scan) => scan.measuring).map((scan) => scan.key)).toEqual([PLACEHOLDER_KEY]);
  });
});

describe('#770 what a key-set series may spend is bounded by the script', () => {
  it('charges requests x ((2,109 + file bytes) + 50) millionths of a dollar, before each run', () => {
    const s = series(['--condition', 'key-set', '--runs', '2'], {
      ANTHROPIC_API_KEY: FAKE_KEY,
      STAND_IN_REQUESTS: '3',
      // The first run ends by a signal and is charged all the same.
      STAND_IN_PLAN: 'SIGTERM,1',
    });
    expect(s.status, s.stderr).toBe(0);
    expect(chargeFor(3)).toBe(7152);
    expect(header(s)).toMatchObject({ condition: 'key-set', hostedRequestsPerRun: 3, microUsdPerRun: 7152 });
    expect(s.spend.map((entry) => [entry.run, entry.microUsd, entry.totalMicroUsd])).toEqual([
      [1, 7152, 7152],
      [2, 7152, 14304],
    ]);
    expect(summary(s)).toMatchObject({ runs: 2, spentMicroUsd: 14304, totalMicroUsd: 14304 });
    expect(s.stdout).toContain('spend: $0.014304 this series, $0.014304 of $11.000000 in total\n');
    // The series runs get the caller's key; the script itself never writes it.
    expect(seriesRuns(s).map((scan) => scan.key)).toEqual([FAKE_KEY, FAKE_KEY]);
    for (const text of [s.stdout, s.stderr, JSON.stringify(s.log), JSON.stringify(s.spend)]) {
      expect(text).not.toContain(FAKE_KEY);
    }
    expect(fs.existsSync(`${s.spendFile}.lock`)).toBe(false);
  });

  it('makes no key-set run when the variable is unset or empty', () => {
    for (const env of [{}, { ANTHROPIC_API_KEY: '' }, { ANTHROPIC_API_KEY: '  ' }] as Record<string, string>[]) {
      const s = series(['--condition', 'key-set', '--runs', '2'], { ...env, STAND_IN_REQUESTS: '3' });
      expect(s.status).toBe(2);
      expect(s.stderr).toContain('refused: ANTHROPIC_API_KEY is empty, so no key-set run is made');
      // Not even the measurement run: nothing was started.
      expect(s.scans).toEqual([]);
      expect(s.spend).toEqual([]);
    }
  });

  it('exits 3 with cap-reached before the run that would pass $11.00', () => {
    const charge = chargeFor(3);
    const env = { ANTHROPIC_API_KEY: FAKE_KEY, STAND_IN_REQUESTS: '3' };
    const seed = (microUsd: number) => (_dir: string, spendFile: string) =>
      fs.writeFileSync(spendFile, `${JSON.stringify({ microUsd })}\n`);

    // One millionth short of room for a single run: no run is made.
    const none = series(['--condition', 'key-set', '--runs', '5'], env, seed(CAP_MICRO_USD - charge + 1));
    expect(none.status).toBe(3);
    expect(none.stderr).toContain('cap-reached: run 1 would take the spend file past $11.000000');
    expect(seriesRuns(none)).toEqual([]);
    expect(none.spend).toHaveLength(1);
    expect(summary(none)).toMatchObject({ runs: 0, stopped: 'cap-reached', spentMicroUsd: 0 });

    // Room for exactly two: the cap itself may be reached, never passed.
    const two = series(['--condition', 'key-set', '--runs', '5'], env, seed(CAP_MICRO_USD - 2 * charge));
    expect(two.status).toBe(3);
    expect(two.stderr).toContain('cap-reached: run 3 would take the spend file past $11.000000');
    expect(seriesRuns(two)).toHaveLength(2);
    expect(two.spend.at(-1)?.totalMicroUsd).toBe(CAP_MICRO_USD);
    expect(summary(two)).toMatchObject({ runs: 2, stopped: 'cap-reached', totalMicroUsd: CAP_MICRO_USD });
  });

  it('refuses a spend file it cannot total, and one another series holds', () => {
    const env = { ANTHROPIC_API_KEY: FAKE_KEY, STAND_IN_REQUESTS: '3' };
    for (const line of ['not a record', '{"microUsd":"12"}', '{"microUsd":-1}']) {
      const s = series(['--condition', 'key-set', '--runs', '1'], env, (_dir, spendFile) =>
        fs.writeFileSync(spendFile, `${JSON.stringify({ microUsd: 5 })}\n${line}\n`),
      );
      expect(s.status).toBe(2);
      expect(s.stderr).toContain('has a line that is not a spend record, so the total is unknown');
      expect(seriesRuns(s)).toEqual([]);
      expect(fs.existsSync(`${s.spendFile}.lock`)).toBe(false);
    }

    const held = series(['--condition', 'key-set', '--runs', '1'], env, (_dir, spendFile) =>
      fs.writeFileSync(`${spendFile}.lock`, '1\n'),
    );
    expect(held.status).toBe(2);
    expect(held.stderr).toContain('another series holds');
    expect(seriesRuns(held)).toEqual([]);
    // The lock belongs to the other series, so this one leaves it.
    expect(fs.existsSync(`${held.spendFile}.lock`)).toBe(true);
  });

  it('refuses a build whose requests the charge would understate', () => {
    const env = { ANTHROPIC_API_KEY: FAKE_KEY, STAND_IN_REQUESTS: '3' };
    const refusals: [Record<string, string>, string][] = [
      [{ STAND_IN_MODEL: 'another-model' }, 'the build asks model "another-model"'],
      [{ STAND_IN_MAX_TOKENS: '11' }, 'the build asks for 11 output tokens, over the 10 a run is charged for'],
      // 2,110 bytes besides the 225-byte file: one over the bound.
      [{ STAND_IN_PROMPT_BYTES: '2110' }, 'the build sends a 2335-byte prompt, over the 2334 a run is charged for'],
      [{ STAND_IN_REQUESTS: '0' }, 'the build makes no hosted-model request on this fixture'],
    ];
    for (const [extra, message] of refusals) {
      const s = series(['--condition', 'key-set', '--runs', '1'], { ...env, ...extra });
      expect(s.status, message).toBe(2);
      expect(s.stderr).toContain(message);
      expect(seriesRuns(s)).toEqual([]);
      expect(s.spend).toEqual([]);
    }
    // At the bound the series runs.
    const atBound = series(['--condition', 'key-set', '--runs', '1'], { ...env, STAND_IN_PROMPT_BYTES: '2109' });
    expect(atBound.status, atBound.stderr).toBe(0);
    expect(atBound.spend).toHaveLength(1);
  });
});

describe('#770 a series that could not show the teardown is refused', () => {
  it('refuses a fixture over 3,000 bytes, one that is not ASCII, and one with a second file', () => {
    const refusals: [Record<string, string | Buffer>, string][] = [
      [{ 'SOUL.md': 'a'.repeat(3001) }, 'refused: the fixture is 3001 bytes, over the 3000 a run is charged for'],
      [{ 'SOUL.md': Buffer.from('# SOUL\ncafé\n') }, 'refused: the fixture is not ASCII'],
      [{ 'SOUL.md': '# SOUL\n', 'AGENTS.md': '# Agents\n' }, 'must hold one regular file, SOUL.md, and nothing else'],
      [{ 'AGENTS.md': '# Agents\n' }, 'must hold one regular file, SOUL.md, and nothing else'],
    ];
    for (const [files, message] of refusals) {
      const s = series(['--condition', 'key-unset', '--runs', '1', '--fixture', fixture(files)]);
      expect(s.status, message).toBe(2);
      expect(s.stderr).toContain(message);
      expect(s.scans).toEqual([]);
    }
    // 3,000 bytes is inside the bound.
    const atBound = series(['--condition', 'key-unset', '--runs', '1', '--fixture', fixture({ 'SOUL.md': 'a'.repeat(3000) })]);
    expect(atBound.status, atBound.stderr).toBe(0);
    expect(header(atBound)?.fixture.bytes).toBe(3000);
  });

  it('refuses a build that opens no model session', () => {
    const s = series(['--condition', 'key-unset', '--runs', '3'], { STAND_IN_SESSIONS: '0' });
    expect(s.status).toBe(2);
    expect(s.stderr).toContain('refused: the build opened no model session on this fixture');
    expect(seriesRuns(s)).toEqual([]);
    expect(s.log).toEqual([]);
  });

  it('refuses arguments it does not know and run counts outside its bounds', () => {
    const refusals: [string[], string][] = [
      [['--condition', 'key-unset', '--runs', '0'], '--runs is a whole number above 0'],
      [['--condition', 'key-unset', '--runs', '1001'], '--runs is at most 1000'],
      [['--condition', 'key-set', '--runs', '151'], '--runs is at most 150 with key-set'],
      [['--condition', 'sometimes', '--runs', '1'], '--condition is key-unset or key-set'],
      [['--condition', 'key-unset', '--runs', '1', '--json'], 'unknown argument "--json"'],
    ];
    for (const [args, message] of refusals) {
      const s = series(args, { ANTHROPIC_API_KEY: FAKE_KEY });
      expect(s.status, message).toBe(2);
      expect(s.stderr).toContain(`refused: ${message}`);
      expect(s.scans).toEqual([]);
    }
  });

  it('makes no run when its log cannot be written', () => {
    const dir = tempDir('hma-deep-series-nolog-');
    // The later --log wins, and its directory does not exist.
    const s = series(['--condition', 'key-unset', '--runs', '1', '--log', path.join(dir, 'missing', 'series.jsonl')]);
    expect(s.status).toBe(2);
    expect(s.stderr).toContain('series.jsonl cannot be written');
    expect(s.scans).toEqual([]);
  });
});
