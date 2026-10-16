/**
 * Watches the real onnxruntime-node in a spawned scan, without replacing it.
 *
 * Writes one stderr line when the process starts, one each time it requires
 * onnxruntime-node, and one each time it creates a session. Each line carries
 * the value ORT_DISABLE_TELEMETRY held at that moment, and the create line
 * also names the onnxruntime-node version that ran. The runtime reads that
 * variable when the first session of the process sets up its environment, so
 * the create line shows that the scan reached that point and what the runtime
 * read there. All three use `fs.writeSync` so they are flushed however the
 * process ends.
 *
 * HMA_TEST_ONNXRUNTIME_NODE, when set, is the directory of another
 * onnxruntime-node install, and the scan loads that one in place of the
 * tree's. That is how a test measures a runtime version the lockfile does not
 * pin.
 */
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const alternate = process.env.HMA_TEST_ONNXRUNTIME_NODE;
const runtimeDir = alternate
  ? path.resolve(alternate)
  : path.dirname(require.resolve('onnxruntime-node/package.json', { paths: [path.join(__dirname, '..', '..')] }));
const runtimeVersion = JSON.parse(fs.readFileSync(path.join(runtimeDir, 'package.json'), 'utf8')).version;

function telemetryVariable() {
  const value = process.env.ORT_DISABLE_TELEMETRY;
  return value === undefined ? '<unset>' : value;
}

fs.writeSync(2, `ORT-PROBE start ORT_DISABLE_TELEMETRY=${telemetryVariable()}\n`);

const realLoad = Module._load;
const wrapped = new WeakSet();

Module._load = function load(request, parent, isMain) {
  if (request !== 'onnxruntime-node') return realLoad.apply(this, arguments);
  fs.writeSync(2, `ORT-PROBE require ORT_DISABLE_TELEMETRY=${telemetryVariable()}\n`);
  const ort = realLoad.call(this, alternate ? runtimeDir : request, parent, isMain);
  const Session = ort.InferenceSession;
  if (!wrapped.has(Session)) {
    wrapped.add(Session);
    const realCreate = Session.create;
    Session.create = function create(...args) {
      fs.writeSync(
        2,
        `ORT-PROBE create ORT_DISABLE_TELEMETRY=${telemetryVariable()} onnxruntime-node=${runtimeVersion}\n`,
      );
      return realCreate.apply(this, args);
    };
  }
  return ort;
};
