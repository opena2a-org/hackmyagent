/**
 * The one place this package loads onnxruntime-node, with the runtime's own
 * telemetry turned off.
 *
 * Official onnxruntime builds from 1.29.0 on carry a telemetry client that is
 * on by default on macOS and Linux. On the first session a process creates it
 * writes a persistent device identifier and an event queue under the home
 * directory (`~/Library/Application Support/Microsoft/DeveloperTools/.onnxruntime`
 * on macOS). Upstream documents `ORT_DISABLE_TELEMETRY=1`, set before the
 * runtime initialises, as preventing the uploader, the events and the
 * identifier. The runtime reads it from the process environment when the
 * first session sets up its environment, and assigning `process.env` on the
 * main thread sets that environment, so the assignment is made here, before
 * the package is required at all. Measured with 1.30.0 on macOS arm64 under
 * an empty HOME: a session created after this assignment writes nothing
 * there, one created without it writes `deviceid` and `onnxruntime.db`.
 *
 * The value is set for the whole process, whatever the caller's environment
 * holds, so no scan starts the client.
 *
 * In a worker thread `process.env` is a copy that native code does not see,
 * so there this assignment does not reach the runtime. The CLI loads it on
 * the main thread.
 */
export function loadOnnxRuntime(): any {
  process.env.ORT_DISABLE_TELEMETRY = '1';
  return require('onnxruntime-node');
}
