'use strict';
// Start recorder for the built CLI, preloaded through NODE_OPTIONS so that it
// reaches every node process a run starts, however that process was spawned:
//
//   NODE_OPTIONS="--require __tests__/helpers/cli-start-recorder.cjs" ...
//
// Appends the arguments of every process whose main script is dist/cli.js to
// the file named by $HMA_TEST_CLI_START_MARKER, one start per line. A preload
// runs before the main script is loaded, so a start is recorded even when
// dist/ has not been built and the process then fails to load it.
//
// Used by __tests__/harness/collection-starts-no-scan.test.ts.

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
