import { fork, type ChildProcess } from 'child_process';
import * as path from 'path';
import http from 'http';

const DVAA_PATH = path.resolve(__dirname, '../../../damn-vulnerable-ai-agent');
const HEALTH_CHECK_TIMEOUT = 30000;
const HEALTH_CHECK_INTERVAL = 500;

/**
 * Manages the DVAA (Damn Vulnerable AI Agent) process lifecycle for integration tests.
 */
export class DVAAManager {
  private process: ChildProcess | null = null;
  private started = false;

  /** Start DVAA with all agents */
  async start(): Promise<void> {
    if (this.started) return;

    const entryPoint = path.join(DVAA_PATH, 'src', 'index.js');

    this.process = fork(entryPoint, [], {
      cwd: DVAA_PATH,
      stdio: 'pipe',
      env: { ...process.env, NODE_ENV: 'test' },
    });

    this.process.on('error', (err) => {
      console.error('DVAA process error:', err.message);
    });

    // Wait for health checks on key ports
    await this.waitForHealth(3000); // Dashboard
    await this.waitForHealth(3001); // SecureBot
    await this.waitForHealth(3003); // LegacyBot

    this.started = true;
  }

  /** Stop DVAA gracefully */
  async stop(): Promise<void> {
    if (!this.process || !this.started) return;

    return new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        if (this.process) {
          this.process.kill('SIGKILL');
        }
        resolve();
      }, 5000);

      this.process!.once('exit', () => {
        clearTimeout(timeout);
        resolve();
      });

      this.process!.kill('SIGTERM');
      this.started = false;
      this.process = null;
    });
  }

  /** Get the DVAA process PID (for ARP to monitor) */
  getPid(): number | undefined {
    return this.process?.pid;
  }

  /** Check if DVAA is running */
  isRunning(): boolean {
    return this.started && this.process !== null;
  }

  private waitForHealth(port: number): Promise<void> {
    const deadline = Date.now() + HEALTH_CHECK_TIMEOUT;

    return new Promise((resolve, reject) => {
      const check = () => {
        if (Date.now() > deadline) {
          reject(new Error(`DVAA health check timed out on port ${port}`));
          return;
        }

        const req = http.get(`http://localhost:${port}/health`, (res) => {
          if (res.statusCode === 200) {
            res.resume();
            resolve();
          } else {
            res.resume();
            setTimeout(check, HEALTH_CHECK_INTERVAL);
          }
        });

        req.on('error', () => {
          setTimeout(check, HEALTH_CHECK_INTERVAL);
        });

        req.setTimeout(2000, () => {
          req.destroy();
          setTimeout(check, HEALTH_CHECK_INTERVAL);
        });
      };

      check();
    });
  }
}
