#!/usr/bin/env node
/**
 * #770: run `scan-soul <dir> --deep` many times on one build and record how
 * every run ended.
 *
 *   node scripts/scan-soul-deep-series.mjs --cli <path>/dist/cli.js \
 *     --condition key-unset --runs 60 --log series.jsonl
 *
 *   node scripts/scan-soul-deep-series.mjs --cli <path>/dist/cli.js \
 *     --condition key-set --runs 150 --stop-on-abort \
 *     --log series.jsonl --spend spend.jsonl
 *
 * `scan-soul --deep` was recorded ending with `recursive_mutex lock failed:
 * Invalid argument` from the C++ runtime and exit code 134, after a complete
 * report, in 2 of 35 runs. The abort is intermittent, so neither a fix nor its
 * absence can be read from one run. The issue asks for a series on the build
 * without the fix that shows the abort at least once, then a series of 60 on
 * the build with the fix in the same environment on the same day. This script
 * is the one way such a series is run, so every series records the same
 * things: the build, the runtime versions, the scanned file, and the ending
 * of every run, zeros included.
 *
 * Start with `key-unset`. It costs nothing, and an abort there makes
 * key-unset the condition to compare the two builds under. Compare two builds
 * only when their series name the same onnxruntime-node version: the range in
 * package.json lets a fresh install of the package resolve a newer runtime
 * than this repository's lockfile does.
 *
 * Options:
 *
 *   --cli <file>          the built CLI to measure. A build without the fix
 *                         is the commit before it, built in a second
 *                         directory.
 *   --condition <c>       `key-unset` removes ANTHROPIC_API_KEY from every
 *                         run, so the hosted-model pass is off and a run
 *                         costs nothing. `key-set` passes the variable
 *                         through, and every run is then billed to that key.
 *   --runs <n>            1 to 1000, and at most 150 with `key-set`.
 *   --log <file>          JSON lines, appended: one `series` record, one
 *                         `run` record per run, one `summary` record.
 *   --spend <file>        JSON lines, appended: one record per `key-set` run,
 *                         written before the run starts. Required with
 *                         `key-set`. Use one file for the whole measurement.
 *   --fixture <dir>       a directory holding one file, SOUL.md. Without it
 *                         the 225-byte SOUL.md from the issue is used.
 *   --stop-on-abort       end the series at the first abort.
 *   --timeout-ms <n>      per run, default 300000.
 *
 * Before the first run the script measures the build at no cost. It runs the
 * scan once with a placeholder in the variable and a preload
 * (scan-soul-deep-series-measure.cjs) that answers the hosted-model requests
 * in-process, and reads back how many requests the build made and whether it
 * opened a model session. A build that opens no session has no session to
 * tear down, so its series could not show the abort and is refused.
 *
 * What a `key-set` series may spend is bounded here and not left to the
 * caller:
 *
 *   - a run is charged before it starts, as
 *     requests x ((2,109 + file bytes) x $0.000001 + $0.00005):
 *     for each request, a bound on its input tokens at the input price and
 *     10 output tokens at the output price of the model named in
 *     PRICED_MODEL;
 *   - the file is at most 3,000 bytes of ASCII, so its byte count bounds its
 *     token count;
 *   - a build whose requests name another model, ask for more output or carry
 *     a longer prompt than that bound is refused, because the charge would
 *     understate it;
 *   - no run starts that would take the spend file past $11.00.
 *
 * Exit codes: 0 the series ran as asked, whatever its runs exited with;
 * 2 the series was refused or could not run; 3 the spend cap was reached.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { createRequire } from 'node:module';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const KEY_VAR = 'ANTHROPIC_API_KEY';
const MEASURE_VAR = 'HMA_DEEP_SERIES_MEASURE_FILE';
// The measurement run never holds the caller's key: even if the preload were
// not loaded, a request made with this value is rejected and billed nothing.
const PLACEHOLDER_KEY = 'not-a-real-key';
const MEASURE_PRELOAD = path.join(path.dirname(fileURLToPath(import.meta.url)), 'scan-soul-deep-series-measure.cjs');

const MAX_FIXTURE_BYTES = 3000;
/** Bound on one request's input tokens besides the scanned file. */
const PROMPT_TOKEN_BOUND = 2109;
/** $0.000001 for one input token of PRICED_MODEL. */
const INPUT_MICRO_USD_PER_TOKEN = 1;
/** The output tokens one request may ask for, and what they cost: $0.00005. */
const MAX_OUTPUT_TOKENS = 10;
const OUTPUT_MICRO_USD_PER_REQUEST = 50;
/** The model those two prices belong to. */
const PRICED_MODEL = 'claude-haiku-4-5-20251001';
/** $11.00, for the whole measurement. */
const CAP_MICRO_USD = 11_000_000;

const MAX_RUNS = 1000;
const MAX_KEY_SET_RUNS = 150;
const DEFAULT_TIMEOUT_MS = 300_000;

const EXIT_REFUSED = 2;
const EXIT_CAP_REACHED = 3;

// The SOUL.md from the reproduction in #770, byte for byte.
const ISSUE_SOUL = `# SOUL.md

## Identity
You are a documentation assistant for an internal wiki.

## Constraints
- Never execute shell commands.
- Only read files under docs/.

## Trust hierarchy
System prompt > operator > user > tool output.
`;

/** A series that is not run. Carries the process exit code. */
class Refusal extends Error {
  constructor(message, exitCode = EXIT_REFUSED) {
    super(message);
    this.exitCode = exitCode;
  }
}

function usd(microUsd) {
  return `$${(microUsd / 1_000_000).toFixed(6)}`;
}

function parseArgs(argv) {
  const opts = { stopOnAbort: false, timeoutMs: DEFAULT_TIMEOUT_MS };
  const value = (i, flag) => {
    if (i >= argv.length) throw new Refusal(`${flag} needs a value`);
    return argv[i];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cli') opts.cli = value(++i, a);
    else if (a === '--condition') opts.condition = value(++i, a);
    else if (a === '--runs') opts.runs = value(++i, a);
    else if (a === '--log') opts.log = value(++i, a);
    else if (a === '--spend') opts.spend = value(++i, a);
    else if (a === '--fixture') opts.fixture = value(++i, a);
    else if (a === '--timeout-ms') opts.timeoutMs = value(++i, a);
    else if (a === '--stop-on-abort') opts.stopOnAbort = true;
    else throw new Refusal(`unknown argument "${a}"`);
  }
  if (!opts.cli) throw new Refusal('--cli <file> is required');
  if (!fs.existsSync(opts.cli) || !fs.statSync(opts.cli).isFile()) {
    throw new Refusal(`--cli ${opts.cli} is not a file`);
  }
  opts.cli = path.resolve(opts.cli);
  if (opts.condition !== 'key-unset' && opts.condition !== 'key-set') {
    throw new Refusal('--condition is key-unset or key-set');
  }
  if (!opts.log) throw new Refusal('--log <file> is required');
  for (const [name, flag] of [['runs', '--runs'], ['timeoutMs', '--timeout-ms']]) {
    if (!/^[1-9]\d*$/.test(String(opts[name]))) throw new Refusal(`${flag} is a whole number above 0`);
    opts[name] = Number(opts[name]);
  }
  if (opts.runs > MAX_RUNS) throw new Refusal(`--runs is at most ${MAX_RUNS}`);
  if (opts.condition === 'key-set') {
    if (opts.runs > MAX_KEY_SET_RUNS) throw new Refusal(`--runs is at most ${MAX_KEY_SET_RUNS} with key-set`);
    if (!opts.spend) throw new Refusal('--spend <file> is required with key-set');
    // Checked before anything runs. An unset variable would turn the series
    // into key-unset runs recorded, and charged, as key-set.
    if (!(process.env[KEY_VAR] ?? '').trim()) {
      throw new Refusal(`${KEY_VAR} is empty, so no key-set run is made`);
    }
  }
  return opts;
}

/** The directory to scan, with the size and digest of its one file. */
function loadFixture(dir, scratch) {
  let target = dir;
  if (!target) {
    target = path.join(scratch, 'fixture');
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, 'SOUL.md'), ISSUE_SOUL);
  }
  target = path.resolve(target);
  let entries;
  try {
    entries = fs.readdirSync(target);
  } catch {
    throw new Refusal(`--fixture ${target} is not a readable directory`);
  }
  // One file, so the bytes that are charged are the bytes that are scanned.
  if (entries.length !== 1 || entries[0] !== 'SOUL.md' || !fs.lstatSync(path.join(target, 'SOUL.md')).isFile()) {
    throw new Refusal(`--fixture ${target} must hold one regular file, SOUL.md, and nothing else`);
  }
  const bytes = fs.readFileSync(path.join(target, 'SOUL.md'));
  if (bytes.length > MAX_FIXTURE_BYTES) {
    throw new Refusal(`the fixture is ${bytes.length} bytes, over the ${MAX_FIXTURE_BYTES} a run is charged for`);
  }
  if (bytes.some((b) => b > 0x7f)) {
    throw new Refusal('the fixture is not ASCII, so its byte count does not bound its token count');
  }
  return { dir: target, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}

/** NODE_OPTIONS with the measuring preload added to whatever is already set. */
function withPreload(nodeOptions) {
  const quoted = `"${MEASURE_PRELOAD.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  return `${nodeOptions ? `${nodeOptions} ` : ''}--require ${quoted}`;
}

/**
 * One run that costs nothing: how many hosted-model requests the build makes
 * on this fixture, what each asks for, and how many model sessions it opens.
 */
function measure(opts, fixture, scratch) {
  const file = path.join(scratch, 'measure.jsonl');
  fs.writeFileSync(file, '');
  const res = spawnSync(process.execPath, [opts.cli, 'scan-soul', fixture.dir, '--deep'], {
    env: {
      ...process.env,
      [KEY_VAR]: PLACEHOLDER_KEY,
      [MEASURE_VAR]: file,
      NODE_OPTIONS: withPreload(process.env.NODE_OPTIONS),
    },
    encoding: 'utf8',
    timeout: opts.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  let records;
  try {
    records = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
  } catch {
    throw new Refusal('the measurement run left a record that cannot be read');
  }
  // Without this line the preload never ran, and a count of zero requests
  // would mean "not counted", not "none made".
  if (!records.some((r) => r.loaded === true)) {
    throw new Refusal('the measurement run did not load the measuring preload, so the build was not measured');
  }
  if (res.error || res.status === null) {
    throw new Refusal(`the measurement run did not finish (${res.error?.code ?? res.signal ?? 'no exit code'})`);
  }
  const requests = records.filter((r) => r.request).map((r) => r.request);
  const sessions = records.filter((r) => r.session === true).length;
  if (sessions === 0) {
    throw new Refusal(
      'the build opened no model session on this fixture, so a series on it cannot show the teardown. ' +
        'Check that the classifier model is installed for the HOME these runs use.',
    );
  }
  return { requests, sessions, exitCode: res.status };
}

/** What one key-set run is charged, or a refusal when the charge would understate it. */
function runCostMicroUsd(measured, fixture) {
  const promptBound = PROMPT_TOKEN_BOUND + fixture.bytes;
  for (const request of measured.requests) {
    if (request.model !== PRICED_MODEL) {
      throw new Refusal(`the build asks model ${JSON.stringify(request.model)}, and the run charge is priced for ${PRICED_MODEL}`);
    }
    if (!Number.isInteger(request.maxTokens) || request.maxTokens > MAX_OUTPUT_TOKENS) {
      throw new Refusal(`the build asks for ${JSON.stringify(request.maxTokens)} output tokens, over the ${MAX_OUTPUT_TOKENS} a run is charged for`);
    }
    if (!Number.isInteger(request.promptBytes) || request.promptBytes > promptBound) {
      throw new Refusal(`the build sends a ${JSON.stringify(request.promptBytes)}-byte prompt, over the ${promptBound} a run is charged for`);
    }
  }
  return measured.requests.length * (promptBound * INPUT_MICRO_USD_PER_TOKEN + OUTPUT_MICRO_USD_PER_REQUEST);
}

/** The total already in the spend file. A line that cannot be read is never counted as zero. */
function readSpend(file) {
  if (!fs.existsSync(file)) return 0;
  let total = 0;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      entry = null;
    }
    if (!entry || !Number.isInteger(entry.microUsd) || entry.microUsd < 0) {
      throw new Refusal(`the spend file ${file} has a line that is not a spend record, so the total is unknown`);
    }
    total += entry.microUsd;
  }
  return total;
}

function describeBuild(cli, timeoutMs) {
  const env = { ...process.env };
  delete env[KEY_VAR];
  const version = spawnSync(process.execPath, [cli, '--version'], { env, encoding: 'utf8', timeout: timeoutMs });
  let onnxruntimeNode = null;
  try {
    const pkg = createRequire(cli).resolve('onnxruntime-node/package.json');
    onnxruntimeNode = JSON.parse(fs.readFileSync(pkg, 'utf8')).version ?? null;
  } catch {
    // Recorded as unknown; the measurement run decides whether a session opens.
  }
  return {
    cli,
    cliVersion: version.status === 0 ? version.stdout.trim().split('\n').pop() : null,
    onnxruntimeNode,
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    osRelease: os.release(),
  };
}

function runOnce(opts, fixture, env) {
  const started = Date.now();
  const res = spawnSync(process.execPath, [opts.cli, 'scan-soul', fixture.dir, '--deep'], {
    env,
    encoding: 'utf8',
    timeout: opts.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const signal = res.signal ?? null;
  const code = res.status;
  // What a shell reports for the run: the exit code, or 128 plus the signal.
  const shellCode = code !== null ? code : signal ? 128 + (os.constants.signals[signal] ?? 0) : null;
  const stderr = res.stderr ?? '';
  return {
    code,
    signal,
    shellCode,
    timedOut: res.error?.code === 'ETIMEDOUT',
    abort: signal === 'SIGABRT' || code === 134,
    abortLine: stderr.includes('recursive_mutex lock failed'),
    reportComplete: (res.stdout ?? '').includes('Scanned with hackmyagent v'),
    ms: Date.now() - started,
  };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const keySet = opts.condition === 'key-set';
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-deep-series-'));
  let lock = null;
  const cleanUp = () => {
    fs.rmSync(scratch, { recursive: true, force: true });
    if (lock) fs.rmSync(lock, { force: true });
  };
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      cleanUp();
      process.exit(130);
    });
  }
  try {
    // Before any run, so a series is never made that cannot be recorded.
    for (const file of keySet ? [opts.log, opts.spend] : [opts.log]) {
      try {
        fs.appendFileSync(file, '');
      } catch {
        throw new Refusal(`${file} cannot be written`);
      }
    }
    const fixture = loadFixture(opts.fixture, scratch);
    const build = describeBuild(opts.cli, opts.timeoutMs);
    const measured = measure(opts, fixture, scratch);
    const costMicroUsd = keySet ? runCostMicroUsd(measured, fixture) : 0;
    if (keySet && measured.requests.length === 0) {
      throw new Refusal('the build makes no hosted-model request on this fixture, so a key-set series would measure key-unset runs');
    }

    let totalMicroUsd = 0;
    if (keySet) {
      // One series at a time on one spend file: two would each read the same
      // total and could pass the cap together.
      lock = `${path.resolve(opts.spend)}.lock`;
      try {
        fs.writeFileSync(lock, `${process.pid}\n`, { flag: 'wx' });
      } catch {
        const held = lock;
        lock = null;
        throw new Refusal(`another series holds ${held}; remove that file if no series is running`);
      }
      totalMicroUsd = readSpend(opts.spend);
    }

    const record = (entry) => fs.appendFileSync(opts.log, `${JSON.stringify(entry)}\n`);
    record({
      type: 'series',
      at: new Date().toISOString(),
      ...build,
      condition: opts.condition,
      fixture: { bytes: fixture.bytes, sha256: fixture.sha256 },
      hostedRequestsPerRun: measured.requests.length,
      sessionsOpened: measured.sessions,
      measurementExitCode: measured.exitCode,
      microUsdPerRun: costMicroUsd,
      runsAsked: opts.runs,
      stopOnAbort: opts.stopOnAbort,
    });
    console.log(`series: scan-soul --deep, ${opts.condition}, ${opts.runs} runs`);
    console.log(
      `  build: ${build.cliVersion ?? 'version unknown'}, onnxruntime-node ${build.onnxruntimeNode ?? 'unknown'}, ` +
        `node ${build.node}, ${build.platform} ${build.arch}`,
    );
    console.log(`  fixture: SOUL.md, ${fixture.bytes} bytes`);
    console.log(
      `  measured at no cost: ${measured.requests.length} hosted-model requests per run, ${measured.sessions} model session(s) opened`,
    );
    if (keySet) {
      console.log(`  charge: ${usd(costMicroUsd)} per run; ${usd(totalMicroUsd)} of ${usd(CAP_MICRO_USD)} already in ${opts.spend}`);
    }

    const env = { ...process.env };
    delete env[MEASURE_VAR];
    if (!keySet) delete env[KEY_VAR];

    const shellCodes = {};
    let runs = 0;
    let aborts = 0;
    let spentMicroUsd = 0;
    let stopped = 'completed';
    for (let run = 1; run <= opts.runs; run++) {
      if (keySet) {
        if (totalMicroUsd + costMicroUsd > CAP_MICRO_USD) {
          stopped = 'cap-reached';
          break;
        }
        // Charged before the run, so a run that is interrupted is still counted.
        totalMicroUsd += costMicroUsd;
        spentMicroUsd += costMicroUsd;
        fs.appendFileSync(
          opts.spend,
          `${JSON.stringify({
            at: new Date().toISOString(),
            cli: opts.cli,
            run,
            hostedRequests: measured.requests.length,
            fixtureBytes: fixture.bytes,
            microUsd: costMicroUsd,
            totalMicroUsd,
          })}\n`,
        );
      }
      const result = runOnce(opts, fixture, env);
      runs++;
      const label = result.shellCode === null ? 'none' : String(result.shellCode);
      shellCodes[label] = (shellCodes[label] ?? 0) + 1;
      if (result.abort) aborts++;
      record({ type: 'run', run, ...result });
      console.log(
        result.timedOut
          ? `run ${run}: timed out after ${opts.timeoutMs} ms`
          : `run ${run}: exit ${label}${result.signal ? ` (${result.signal})` : ''}`,
      );
      if (result.abort && opts.stopOnAbort) {
        stopped = 'abort';
        break;
      }
    }

    record({ type: 'summary', at: new Date().toISOString(), runs, shellCodes, aborts, stopped, spentMicroUsd, totalMicroUsd });
    const tally = Object.keys(shellCodes)
      .sort((a, b) => Number(a) - Number(b))
      .map((code) => `exit ${code} x ${shellCodes[code]}`)
      .join(', ');
    console.log(`summary: ${runs} runs${tally ? `, ${tally}` : ''}, aborts ${aborts}`);
    if (keySet) console.log(`spend: ${usd(spentMicroUsd)} this series, ${usd(totalMicroUsd)} of ${usd(CAP_MICRO_USD)} in total`);
    if (stopped === 'cap-reached') {
      throw new Refusal(`cap-reached: run ${runs + 1} would take the spend file past ${usd(CAP_MICRO_USD)}`, EXIT_CAP_REACHED);
    }
  } finally {
    cleanUp();
  }
}

try {
  main();
} catch (err) {
  if (!(err instanceof Refusal)) throw err;
  console.error(err.exitCode === EXIT_CAP_REACHED ? err.message : `refused: ${err.message}`);
  process.exitCode = err.exitCode;
}
