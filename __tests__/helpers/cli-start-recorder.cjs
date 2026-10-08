'use strict';
// Start recorder for the built CLI, preloaded through NODE_OPTIONS:
//
//   NODE_OPTIONS="--require __tests__/helpers/cli-start-recorder.cjs" ...
//
// Appends the arguments of every process whose main script is dist/cli.js to
// the file named by $HMA_TEST_CLI_START_MARKER, one start per line. A preload
// runs before the main script is loaded, so a start is recorded even when
// dist/ has not been built and the process then fails to load it.
//
// NODE_OPTIONS reaches a child only through the child's environment, and a
// spawn whose `env` replaces process.env (`env: { PATH, HOME }`) drops it
// along with the marker. So the recorder also wraps the spawn functions of
// node:child_process in every process it is loaded into, and adds its own
// NODE_OPTIONS and marker variables to any `env` a spawn passes without them.
// A start is then seen however the env of the spawn is built. What it cannot
// see is a child that clears its own environment before it starts node, such
// as `sh -c 'env -i node dist/cli.js'`.
//
// Used by __tests__/harness/collection-starts-no-scan.test.ts, which preloads
// __tests__/helpers/net-recorder.cjs alongside, so $HMA_TEST_NET_MARKER is
// forwarded too.

const fs = require('node:fs');
const path = require('node:path');

const MARKER = process.env.HMA_TEST_CLI_START_MARKER;
const main = process.argv[1];

if (MARKER && main) {
  let resolved = path.resolve(main);
  try {
    resolved = fs.realpathSync(resolved);
  } catch {
    // Not built: the path as given still names the script.
  }
  const parts = resolved.split(path.sep);
  if (parts[parts.length - 1] === 'cli.js' && parts[parts.length - 2] === 'dist') {
    try {
      fs.appendFileSync(MARKER, JSON.stringify(process.argv.slice(2)) + '\n');
    } catch {
      // Never let instrumentation change the behaviour of the process.
    }
  }
}

if (MARKER) {
  const childProcess = require('node:child_process');
  const { promisify } = require('node:util');

  // Captured at load: a test that later edits process.env does not change
  // what is forwarded.
  const PRELOAD = process.env.NODE_OPTIONS || '';
  const FORWARDED = {};
  for (const name of ['HMA_TEST_CLI_START_MARKER', 'HMA_TEST_NET_MARKER']) {
    if (process.env[name]) FORWARDED[name] = process.env[name];
  }

  /** The env a child gets: the spawn's own, plus what the recorders need. */
  const withRecorders = (env) => {
    const out = { ...env };
    const own = out.NODE_OPTIONS == null ? '' : String(out.NODE_OPTIONS);
    if (PRELOAD && !own.includes(PRELOAD)) out.NODE_OPTIONS = [own, PRELOAD].filter(Boolean).join(' ');
    for (const [name, value] of Object.entries(FORWARDED)) {
      if (out[name] === undefined) out[name] = value;
    }
    return out;
  };

  /**
   * The options object is the first plain object after the command: args is
   * an array and the callback a function. A spawn with no `env` inherits
   * process.env, which already carries both.
   */
  const forward = (args) => {
    try {
      for (let i = 1; i < args.length; i++) {
        const a = args[i];
        if (a === null || typeof a !== 'object' || Array.isArray(a)) continue;
        if (a.env === null || typeof a.env !== 'object') return args;
        const copy = args.slice();
        copy[i] = { ...a, env: withRecorders(a.env) };
        return copy;
      }
    } catch {
      // Never let instrumentation change the behaviour of the process.
    }
    return args;
  };

  // Each is wrapped on its own: execFileSync and friends call the module's
  // internal spawn, not the exported one.
  for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork']) {
    const orig = childProcess[name];
    if (typeof orig !== 'function') continue;
    const wrapped = function (...args) {
      return orig.apply(this, forward(args));
    };
    // promisify(exec) and promisify(execFile) call this, not the function.
    const custom = orig[promisify.custom];
    if (typeof custom === 'function') {
      wrapped[promisify.custom] = function (...args) {
        return custom.apply(this, forward(args));
      };
    }
    childProcess[name] = wrapped;
  }
  // `import { spawnSync } from 'node:child_process'` reads these bindings.
  require('node:module').syncBuiltinESMExports();
}
