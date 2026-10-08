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
 * The pins are read from MODEL_FILES in the built classifier module, the
 * same module the spawned CLI checks its cache with, so a new model's pins
 * reach this preload without an edit here.
 */
const path = require('node:path');

const standInDir = process.env.HMA_TEST_STAND_IN_MODEL_DIR;
if (!standInDir) {
  throw new Error('stub-model-hash-preload: HMA_TEST_STAND_IN_MODEL_DIR is not set');
}

const { TMEClassifier, MODEL_FILES } = require(
  path.join(__dirname, '..', '..', 'dist', 'nanomind-core', 'inference', 'tme-classifier.js'),
);
if (!Array.isArray(MODEL_FILES) || MODEL_FILES.length === 0) {
  throw new Error('stub-model-hash-preload: dist has no MODEL_FILES export; run `npm run build`');
}
const PINNED_SHA256 = Object.fromEntries(MODEL_FILES.map(f => [f.name, f.sha256]));
const realHash = TMEClassifier.hashFileSync;

TMEClassifier.hashFileSync = function hashFileSync(filePath) {
  const resolved = path.resolve(String(filePath));
  const pinned = PINNED_SHA256[path.basename(resolved)];
  if (pinned && path.dirname(resolved) === path.resolve(standInDir)) return pinned;
  return realHash.call(this, filePath);
};
