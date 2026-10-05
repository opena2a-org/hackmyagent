// Fixture suite for __tests__/harness/temp-dir-cleanup.test.ts, run there with
// an empty TMPDIR. It calls `tempDir` from every place a real test file does,
// and ends tests in every way a real one can: passing, failing, cancelled, and
// with an entry left unreadable. The outcome counts are asserted by the parent;
// one failure is deliberate.
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { tempDir } from '../temp-dir';

const atCollection = tempDir('fixture-collect-');
let inBeforeAll = '';
let inBeforeEach = '';
let fromEarlierTest = '';

beforeAll(() => {
  inBeforeAll = tempDir('fixture-beforeall-');
});

beforeEach(() => {
  inBeforeEach = tempDir('fixture-beforeeach-');
});

describe('tempDir fixture', () => {
  it('passes after a child process writes into the HOME it was given', () => {
    const home = tempDir('fixture-home-');
    const child = spawnSync(
      process.execPath,
      ['-e', "const fs=require('fs'),p=require('path');const d=p.join(process.env.HOME,'.opena2a');fs.mkdirSync(d);fs.writeFileSync(p.join(d,'state.json'),'{}')"],
      { env: { ...process.env, HOME: home } },
    );
    expect(child.status).toBe(0);
    expect(fs.existsSync(path.join(home, '.opena2a', 'state.json'))).toBe(true);
    fromEarlierTest = home;
  });

  it('sees the previous test directory removed and the file-scoped ones still present', () => {
    expect(fromEarlierTest).not.toBe('');
    expect(fs.existsSync(fromEarlierTest)).toBe(false);
    expect(fs.existsSync(atCollection)).toBe(true);
    expect(fs.existsSync(inBeforeAll)).toBe(true);
    expect(fs.existsSync(inBeforeEach)).toBe(true);
  });

  it('FIXTURE-FAILS on purpose after creating a directory', () => {
    tempDir('fixture-failing-');
    expect('this test fails on purpose').toBe('so the run shows removal after a failure');
  });

  it('is cancelled with ctx.skip() after creating a directory', (ctx) => {
    tempDir('fixture-skipped-');
    ctx.skip();
  });

  it('leaves an entry it made unreadable', () => {
    const locked = path.join(tempDir('fixture-unreadable-'), 'locked');
    fs.mkdirSync(locked);
    fs.writeFileSync(path.join(locked, 'inner'), 'x');
    fs.chmodSync(locked, 0o000);
  });

  // Non-vacuity: the parent turns this on to show the cell sees a directory
  // the helper was never told about.
  if (process.env.HMA_TEMP_DIR_FIXTURE_LEAK === '1') {
    it('creates a directory behind the helper', () => {
      fs.mkdirSync(path.join(os.tmpdir(), 'fixture-raw-leak'));
    });
  }
});
