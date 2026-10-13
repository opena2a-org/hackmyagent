/**
 * Stands in for the built CLI under scripts/scan-soul-deep-series.mjs, so the
 * series script can be tested without a build, a model or the network.
 *
 * It answers `--version` and `scan-soul <dir> --deep`. A scan opens
 * STAND_IN_SESSIONS sessions through `onnxruntime-node` (the test preloads
 * stub-onnxruntime-preload.cjs, so no native library loads), appends one line
 * to the STAND_IN_STATE file saying what it saw, prints a report footer and
 * ends the way STAND_IN_PLAN says.
 *
 * It sends hosted-model requests only in the series script's measurement run,
 * and only after that run's preload has recorded that it is installed, so no
 * test run reaches the network: a series run with the key set records the key
 * as set and sends nothing.
 *
 *   STAND_IN_PLAN        endings of the series runs, in order, comma
 *                        separated; the last one repeats. A number is an exit
 *                        code, `134` also prints the abort line from #770,
 *                        and a signal name ends the run by that signal.
 *   STAND_IN_REQUESTS    hosted-model requests made in the measurement run.
 *   STAND_IN_MODEL, STAND_IN_MAX_TOKENS, STAND_IN_PROMPT_BYTES
 *                        what each of those requests asks for, besides the
 *                        scanned file.
 */
const fs = require('node:fs');
const path = require('node:path');

const args = process.argv.slice(2);
if (args[0] === '--version') {
  process.stdout.write('hackmyagent 0.0.0-stand-in\n');
  process.exit(0);
}

const ABORT_LINE =
  'libc++abi: terminating due to uncaught exception of type std::__1::system_error: recursive_mutex lock failed: Invalid argument\n';

const stateFile = process.env.STAND_IN_STATE;
const measureFile = process.env.HMA_DEEP_SERIES_MEASURE_FILE;
const key = process.env.ANTHROPIC_API_KEY;
const measuring = Boolean(measureFile);

(async () => {
  const sessions = Number(process.env.STAND_IN_SESSIONS ?? 1);
  if (sessions > 0) {
    const ort = require('onnxruntime-node');
    for (let i = 0; i < sessions; i++) await ort.InferenceSession.create();
  }

  let requests = 0;
  if (key && measuring && fs.readFileSync(measureFile, 'utf8').includes('"loaded":true')) {
    const scanned = fs.readFileSync(path.join(args[1], 'SOUL.md'), 'utf8');
    const prompt = 'q'.repeat(Number(process.env.STAND_IN_PROMPT_BYTES ?? 100)) + scanned;
    for (let i = 0; i < Number(process.env.STAND_IN_REQUESTS ?? 0); i++) {
      await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'x-api-key': key, 'content-type': 'application/json' },
        body: JSON.stringify({
          model: process.env.STAND_IN_MODEL ?? 'claude-haiku-4-5-20251001',
          max_tokens: Number(process.env.STAND_IN_MAX_TOKENS ?? 10),
          messages: [{ role: 'user', content: prompt }],
        }),
      });
      requests++;
    }
  }

  const earlier = fs.existsSync(stateFile)
    ? fs.readFileSync(stateFile, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line))
    : [];
  fs.appendFileSync(
    stateFile,
    `${JSON.stringify({ measuring, key: key ?? null, requests, args })}\n`,
  );
  fs.writeSync(1, 'report\n  Scanned with hackmyagent v0.0.0-stand-in\n');
  if (measuring) process.exit(1);

  const plan = (process.env.STAND_IN_PLAN ?? '1').split(',');
  const seriesRunsSoFar = earlier.filter((entry) => !entry.measuring).length;
  const ending = plan[Math.min(seriesRunsSoFar, plan.length - 1)];
  if (ending.startsWith('SIG')) {
    process.kill(process.pid, ending);
    // Held open until the signal is delivered.
    setTimeout(() => {}, 60_000);
    return;
  }
  if (ending === '134') fs.writeSync(2, ABORT_LINE);
  process.exit(Number(ending));
})();
