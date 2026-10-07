/**
 * NanoMind Daemon Lifecycle Manager
 *
 * Manages the NanoMind daemon process for HMA. Provides:
 * - Health check against running daemon
 * - Auto-start if daemon is not running
 * - Graceful shutdown on process exit
 *
 * The daemon runs on localhost:47200 and provides semantic inference
 * for the AST compilation pipeline. It is optional -- all NanoMind
 * features gracefully degrade when the daemon is unavailable.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, relative, sep } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_PORT = 47200;
const HEALTH_TIMEOUT_MS = 2000;
const STARTUP_WAIT_MS = 3000;
const STARTUP_POLL_MS = 200;
const PID_FILE = join(homedir(), '.nanomind', 'daemon.pid');
const DAEMON_PACKAGE = '@nanomind/daemon';
const DAEMON_BIN = 'nanomind-daemon';

let managedProcess: ChildProcess | null = null;

/**
 * Check if the NanoMind daemon is responding on its health endpoint.
 */
export async function isDaemonRunning(port: number = DEFAULT_PORT): Promise<boolean> {
  try {
    const resp = await fetch(`http://127.0.0.1:${port}/health`, {
      signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
    });
    return resp.ok;
  } catch {
    return false;
  }
}

/**
 * Ensure the NanoMind daemon is running. If not running, attempt to start it.
 * Returns true if the daemon is available after this call.
 *
 * Start order:
 * 1. Check if already running (health check)
 * 2. Check PID file for an existing process
 * 3. Start the daemon CLI that resolveDaemonCommand() finds, if any
 */
export async function ensureDaemon(port: number = DEFAULT_PORT): Promise<boolean> {
  // Already running?
  if (await isDaemonRunning(port)) {
    return true;
  }

  // Check if there's a stale PID file with a live process
  if (existsSync(PID_FILE)) {
    try {
      const pid = parseInt(readFileSync(PID_FILE, 'utf-8').trim(), 10);
      process.kill(pid, 0); // Check if alive (throws if not)
      // Process exists but not responding -- give it a moment
      await sleep(1000);
      if (await isDaemonRunning(port)) {
        return true;
      }
    } catch {
      // Stale PID file, process is dead -- proceed to start
    }
  }

  // Try to start the daemon
  const started = await startDaemon(port);
  if (!started) {
    return false;
  }

  // Wait for daemon to become healthy
  const deadline = Date.now() + STARTUP_WAIT_MS;
  while (Date.now() < deadline) {
    if (await isDaemonRunning(port)) {
      return true;
    }
    await sleep(STARTUP_POLL_MS);
  }

  return false;
}

/** How to start the daemon: an absolute interpreter path and its arguments. */
export interface DaemonCommand {
  command: string;
  args: string[];
}

/**
 * Work out how to start the NanoMind daemon, or return null when no daemon
 * CLI is installed where HMA can find it.
 *
 * The interpreter is the Node binary already running HMA and the daemon CLI
 * is an absolute path. No command name is looked up on PATH, so a `node` or
 * `nanomind-daemon` earlier on PATH is never what runs.
 *
 * Search order:
 * 1. Monorepo sibling checkout (development)
 * 2. The @nanomind/daemon package, resolved the way Node resolves this
 *    package's own dependencies: a `node_modules` directory at or above this
 *    package, then NODE_PATH and Node's global folders. When HMA itself is
 *    installed globally, that includes a global @nanomind/daemon install. The
 *    package's `bin` must name a file inside the package directory.
 *
 * A daemon this search does not find is not started; start it with
 * `nanomind-daemon start` and HMA finds it through the health check.
 *
 * `baseDir` and `execPath` are parameters so tests can supply their own.
 */
export function resolveDaemonCommand(
  baseDir: string = __dirname,
  execPath: string = process.execPath,
): DaemonCommand | null {
  const cli = findDaemonCli(baseDir);
  return cli ? { command: execPath, args: [cli, 'start'] } : null;
}

/**
 * Where a monorepo sibling checkout keeps the daemon CLI, relative to the
 * directory that holds both checkouts.
 */
export const SIBLING_DAEMON_CLI = join('nanomind', 'packages', 'nanomind-daemon', 'dist', 'cli.js');

function findDaemonCli(baseDir: string): string | null {
  const monorepoCli = join(baseDir, '..', '..', '..', '..', SIBLING_DAEMON_CLI);
  if (existsSync(monorepoCli)) {
    return monorepoCli;
  }

  try {
    const manifestPath = createRequire(join(baseDir, 'noop.js')).resolve(`${DAEMON_PACKAGE}/package.json`);
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    const bin = typeof manifest.bin === 'string' ? manifest.bin : manifest.bin?.[DAEMON_BIN];
    if (typeof bin !== 'string') {
      return null;
    }
    const packageDir = dirname(manifestPath);
    const cli = join(packageDir, bin);
    if (!existsSync(cli)) {
      return null;
    }
    // A `bin` of `../../x.js`, or a link that leads out of the package,
    // would hand the Node binary a file the package does not contain.
    return isInside(realpathSync(packageDir), realpathSync(cli)) ? cli : null;
  } catch {
    // Not installed, or a manifest that cannot be read
    return null;
  }
}

function isInside(dir: string, path: string): boolean {
  const rel = relative(dir, path);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/**
 * Start the NanoMind daemon process.
 */
async function startDaemon(port: number): Promise<boolean> {
  const launch = resolveDaemonCommand();
  if (!launch) {
    return false;
  }

  const env = { ...process.env, NANOMIND_PORT: String(port) };
  return spawnDaemon(launch.command, launch.args, env);
}

/**
 * Resolves true once the process has launched, false if it could not be.
 *
 * `spawn` does not throw for a command that is not installed: it returns a
 * ChildProcess and reports ENOENT later as an 'error' event. Reporting success
 * at return time sent every scan on a machine without the daemon into the full
 * STARTUP_WAIT_MS health-poll loop for a process that never existed — about
 * 3s per scan, most of the wall time of a small one.
 */
function spawnDaemon(command: string, args: string[], env: NodeJS.ProcessEnv): Promise<boolean> {
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawn(command, args, {
        env,
        stdio: 'ignore',
        detached: true,
      });
    } catch {
      resolve(false);
      return;
    }

    child.unref();

    child.on('spawn', () => {
      managedProcess = child;
      resolve(true);
    });

    // Stays attached after launch: a later 'error' with no listener would
    // throw out of the scan.
    child.on('error', () => {
      if (managedProcess === child) managedProcess = null;
      resolve(false);
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Register cleanup on process exit
process.on('exit', () => {
  if (managedProcess && !managedProcess.killed) {
    try {
      managedProcess.kill('SIGTERM');
    } catch {
      // Process already gone
    }
  }
});
