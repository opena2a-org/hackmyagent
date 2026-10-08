// Fixture for __tests__/harness/collection-starts-no-scan.test.ts: the shape
// of starts-cli.fixture.ts, with every spawn given an `env` that replaces
// process.env instead of extending it. That env carries neither NODE_OPTIONS
// nor the marker variables, which is how a recorder preloaded into the run
// stopped reaching the child (#911). Several suites spawn the CLI this way to
// keep the developer's environment out of the run.
//
// `-V` tells this start apart from the `--version` of starts-cli.fixture.ts.
// The second child makes its request to a host the other fixture does not
// use, so the request is told apart the same way.
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const CLI = join(__dirname, '..', '..', '..', 'dist', 'cli.js');
const REPLACED_ENV = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' };

describe('fixture: work started with a replaced env while the file is collected', () => {
  spawnSync(process.execPath, [CLI, '-V'], { encoding: 'utf8', timeout: 60_000, env: REPLACED_ENV });
  spawnSync(
    process.execPath,
    ['-e', "require('node:https').get('https://localhost:9/replaced-env').on('error', () => {})"],
    { encoding: 'utf8', timeout: 60_000, env: REPLACED_ENV },
  );

  it('has a test, so the file is listed', () => {
    expect(true).toBe(true);
  });
});
