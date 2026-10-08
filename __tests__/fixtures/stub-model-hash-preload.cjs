/**
 * Makes a spawned CLI read the stand-in model files in one directory as
 * pinned, so a scan uses that cache without downloading the model.
 *
 * The classifier loads a cached model file only at its pinned size and
 * sha256, and fetches any other file again. A test that seeds a cache with
 * stand-in files of the pinned sizes sets HMA_TEST_STAND_IN_MODEL_DIR to that
 * directory; this preload answers the pinned sha256 for the model files in it
 * and leaves every other path to the real hash. The size check still runs.
 *
 * The values are the pins in src/nanomind-core/inference/tme-classifier.ts.
 */
const path = require('node:path');

const PINNED_SHA256 = {
  'tokenizer.json': '5ace7e6441505cf24dfb84d10b237c66edccaece075b3c5b0736c007d65355ce',
  'nanomind-tme.onnx': '1c9c6db00385e0e871ee6d2508d90a3210eddd4abf45365151fb859d8abab9eb',
  'nanomind-tme.onnx.data': '1367c0d3086b8d5c698dc37ae309c3afdb41ffa4d35ecac9b8f1882ffeb1d018',
};

const standInDir = process.env.HMA_TEST_STAND_IN_MODEL_DIR;
if (!standInDir) {
  throw new Error('stub-model-hash-preload: HMA_TEST_STAND_IN_MODEL_DIR is not set');
}

const { TMEClassifier } = require(
  path.join(__dirname, '..', '..', 'dist', 'nanomind-core', 'inference', 'tme-classifier.js'),
);
const realHash = TMEClassifier.hashFileSync;

TMEClassifier.hashFileSync = function hashFileSync(filePath) {
  const resolved = path.resolve(String(filePath));
  const pinned = PINNED_SHA256[path.basename(resolved)];
  if (pinned && path.dirname(resolved) === path.resolve(standInDir)) return pinned;
  return realHash.call(this, filePath);
};
