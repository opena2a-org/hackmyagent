/**
 * The preload that lets a spawned scan use a stand-in model cache answers the
 * classifier's own pinned sha256 values, not a copy of them.
 *
 * The pins used to be written out in tme-classifier.ts, in this preload and in
 * the tests, with nothing tying the copies together. A pin changed in the
 * classifier alone left the preload answering the old value, so a spawned
 * scan seeded with the stand-in cache found it unpinned, printed "NanoMind:
 * downloading", and failed wherever the download could not complete. The
 * preload now reads MODEL_FILES from the built classifier, and this test
 * checks that its answers are those pins.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { MODEL_FILES } from '../../src/nanomind-core/inference/tme-classifier';

const HASH_PRELOAD = path.join(__dirname, '..', 'fixtures', 'stub-model-hash-preload.cjs');
const BUILT_CLASSIFIER = path.join(
  __dirname, '..', '..', 'dist', 'nanomind-core', 'inference', 'tme-classifier.js',
);

// Prints, as JSON, the sha256 the classifier reads for each named file in the
// stand-in directory and for a file of the same name outside it.
const PROBE = `
const path = require('node:path');
const { TMEClassifier } = require(process.env.PROBE_CLASSIFIER);
const out = { inside: {}, outside: {} };
for (const name of JSON.parse(process.env.PROBE_NAMES)) {
  out.inside[name] = TMEClassifier.hashFileSync(path.join(process.env.HMA_TEST_STAND_IN_MODEL_DIR, name));
  out.outside[name] = TMEClassifier.hashFileSync(path.join(process.env.PROBE_OUTSIDE_DIR, name));
}
process.stdout.write(JSON.stringify(out));
`;

let standIn = '';
let outside = '';

beforeAll(assertDistFreshIfPresent);

beforeAll(() => {
  if (!existsSync(BUILT_CLASSIFIER)) throw new Error('dist missing — run `npm run build`');
  const root = tempDir('hma-pin-preload-');
  standIn = path.join(root, 'models');
  outside = path.join(root, 'elsewhere');
  mkdirSync(standIn);
  mkdirSync(outside);
  for (const { name } of MODEL_FILES) {
    writeFileSync(path.join(standIn, name), '');
    writeFileSync(path.join(outside, name), '');
  }
});

function probe(): { inside: Record<string, string>; outside: Record<string, string> } {
  const res = spawnSync(process.execPath, ['--require', HASH_PRELOAD, '-e', PROBE], {
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HMA_TEST_STAND_IN_MODEL_DIR: standIn,
      PROBE_CLASSIFIER: BUILT_CLASSIFIER,
      PROBE_OUTSIDE_DIR: outside,
      PROBE_NAMES: JSON.stringify(MODEL_FILES.map(f => f.name)),
    },
    timeout: 30_000,
  });
  expect(res.status, res.stderr).toBe(0);
  return JSON.parse(res.stdout);
}

describe('stub-model-hash-preload', () => {
  it('answers the pinned sha256 in MODEL_FILES for every stand-in model file', () => {
    expect(MODEL_FILES.length).toBeGreaterThan(0);
    const expected = Object.fromEntries(MODEL_FILES.map(f => [f.name, f.sha256]));
    expect(probe().inside).toEqual(expected);
  });

  it('leaves a file outside the stand-in directory to the real hash', () => {
    // Every file there is empty, so each reads as the sha256 of no bytes.
    const empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const expected = Object.fromEntries(MODEL_FILES.map(f => [f.name, empty]));
    expect(probe().outside).toEqual(expected);
  });
});
