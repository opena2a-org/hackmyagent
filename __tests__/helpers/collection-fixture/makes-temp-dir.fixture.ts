// Fixture for __tests__/harness/collection-starts-no-scan.test.ts: a file that
// creates a temporary directory from its describe body. vitest runs a describe
// body while it collects the file, and `vitest list` runs no hook, so nothing
// removes the directory.
import { describe, it, expect } from 'vitest';
import { tempDir } from '../temp-dir';

describe('fixture: a directory created while the file is collected', () => {
  tempDir('hma-collect-fixture-');

  it('has a test, so the file is listed', () => {
    expect(true).toBe(true);
  });
});
