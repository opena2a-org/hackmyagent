'use strict';
/**
 * Shortens the time the spawned CLI gives a `git` it starts before ending it.
 *
 * `check <URL>` gives `git clone` 120 s, a number set where the clone is
 * started, so a spawn test of a clone that never answers would wait that
 * long. Loaded with `node --require <this file>`, this replaces the `timeout`
 * of every `execFile('git', ...)` call that sets one with the number of
 * milliseconds in $HMA_TEST_GIT_TIMEOUT_MS. Nothing else about the call
 * changes: git is started, left to run, and ended by Node's own timer, so the
 * error the CLI catches is the one a clone that runs out of time gives.
 */
const childProcess = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');
const { promisify } = require('node:util');

const LIMIT_MS = Number(process.env.HMA_TEST_GIT_TIMEOUT_MS);

if (Number.isFinite(LIMIT_MS) && LIMIT_MS > 0) {
  const execFile = childProcess.execFile;
  const execFileAsync = promisify(execFile);

  const withLimit = (args) => (args[0] === 'git'
    ? args.map((arg) => (arg !== null && typeof arg === 'object' && !Array.isArray(arg) && arg.timeout > 0
      ? { ...arg, timeout: LIMIT_MS }
      : arg))
    : args);

  childProcess.execFile = function (...args) {
    return execFile.apply(this, withLimit(args));
  };
  // `promisify(execFile)` takes its implementation from this property.
  childProcess.execFile[promisify.custom] = (...args) => execFileAsync(...withLimit(args));
  syncBuiltinESMExports();
}
