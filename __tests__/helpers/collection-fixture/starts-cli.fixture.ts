// Fixture for __tests__/harness/collection-starts-no-scan.test.ts: a file that
// starts the built CLI and makes a request from its describe body, the shape
// that test exists to catch. vitest runs a describe body while it collects the
// file, so both happen under `vitest list`, which runs no test.
//
// `--version` is enough to be seen starting; the request goes to the discard
// port on the loopback address and is refused there.
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import https from 'node:https';
import { join } from 'node:path';

const CLI = join(__dirname, '..', '..', '..', 'dist', 'cli.js');

describe('fixture: work started while the file is collected', () => {
  spawnSync(process.execPath, [CLI, '--version'], { encoding: 'utf8', timeout: 60_000 });
  https.get('https://127.0.0.1:9/collection-fixture').on('error', () => {});

  it('has a test, so the file is listed', () => {
    expect(true).toBe(true);
  });
});
