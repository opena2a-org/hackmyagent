import { spawnSync } from 'node:child_process';

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

/**
 * Whether requiring onnxruntime-node in this process writes nothing to
 * stdout or stderr.
 *
 * On Linux arm64 under Apple silicon virtualization, loading the library
 * prints
 *
 *   onnxruntime cpuid_info warning: Unknown CPU vendor. cpuinfo_vendor value: 0
 *
 * to stderr. It is written while the shared library is being loaded: a static
 * initializer in `libonnxruntime.so.1` builds the runtime's CPU description
 * during `dlopen`, before any onnxruntime logger exists, and with no logger
 * onnxruntime writes the warning to `std::cerr` itself. `env.logLevel` and the
 * session's `logSeverityLevel` are both applied later, so neither can silence
 * it, and nothing in Node can redirect a native write to file descriptor 2.
 * Once the library is loaded into a scan the line is already in the report.
 *
 * So, on Linux, the library is first loaded in a child Node process whose
 * output is captured and discarded. If that load wrote anything naming
 * onnxruntime, the scan does not load the library and keeps vocabulary
 * scoring, the same result as any other failure to start neural inference.
 * The child runs without NODE_OPTIONS, so a preload set for the scan does not
 * print into the captured output.
 *
 * macOS does not detect the CPU this way and is not probed. If the probe
 * cannot run at all, the answer is yes and the library loads as it did
 * before. The answer is kept for the life of the process.
 */
let quietLoad: boolean | undefined;

export function onnxRuntimeLoadsQuietly(): boolean {
  if (quietLoad !== undefined) return quietLoad;
  if (process.platform !== 'linux') {
    quietLoad = true;
    return quietLoad;
  }
  let resolved: string;
  try {
    resolved = require.resolve('onnxruntime-node');
  } catch {
    // Not installed: the require that follows fails on its own, and its
    // caller already handles that.
    quietLoad = true;
    return quietLoad;
  }
  quietLoad = moduleLoadsQuietly(resolved);
  return quietLoad;
}

/**
 * Requires `modulePath` in a child Node process and reports whether that
 * wrote nothing naming onnxruntime to stdout or stderr. Exported for its test.
 */
export function moduleLoadsQuietly(modulePath: string): boolean {
  const env: NodeJS.ProcessEnv = { ...process.env, ORT_DISABLE_TELEMETRY: '1' };
  delete env.NODE_OPTIONS;
  const run = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(modulePath)})`], {
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
    windowsHide: true,
  });
  if (run.error) return true;
  return !/onnxruntime/i.test(`${run.stdout ?? ''}${run.stderr ?? ''}`);
}
