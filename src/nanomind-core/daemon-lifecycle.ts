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
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_PORT = 47200;
const HEALTH_TIMEOUT_MS = 2000;
const STARTUP_WAIT_MS = 3000;
const STARTUP_POLL_MS = 200;
const PID_FILE = join(homedir(), '.nanomind', 'daemon.pid');

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
 * 3. Try to start via the nanomind-daemon CLI package
 * 4. Try to start via the monorepo sibling path
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

/**
 * Start the NanoMind daemon process.
 * Tries multiple paths to find the daemon CLI.
 */
async function startDaemon(port: number): Promise<boolean> {
  const env = { ...process.env, NANOMIND_PORT: String(port) };

  // Path 1: Monorepo sibling (development)
  const monorepoPath = join(__dirname, '..', '..', '..', '..', 'nanomind', 'packages', 'nanomind-daemon', 'dist', 'cli.js');
  if (existsSync(monorepoPath)) {
    return spawnDaemon('node', [monorepoPath, 'start'], env);
  }

  // Path 2: Installed @nanomind/daemon package
  const localBin = join(__dirname, '..', '..', 'node_modules', '.bin', 'nanomind-daemon');
  if (existsSync(localBin)) {
    return spawnDaemon(localBin, ['start'], env);
  }

  // Path 3: Global nanomind-daemon
  return spawnDaemon('nanomind-daemon', ['start'], env);
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
