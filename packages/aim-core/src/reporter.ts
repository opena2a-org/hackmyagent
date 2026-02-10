import * as https from 'https';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import type { AuditEvent } from './types';

const QUEUE_FILE = 'report-queue.jsonl';
const MAX_BATCH_SIZE = 50;
const MAX_QUEUE_SIZE = 1000;
const FLUSH_INTERVAL_MS = 30_000;

export interface ReporterOptions {
  /** AIM server URL (e.g., https://aim.opena2a.org) */
  serverUrl: string;
  /** Agent ID for authentication */
  agentId: string;
  /** Data directory for offline queue persistence */
  dataDir: string;
  /** Optional API token */
  apiToken?: string;
  /** Flush interval in ms (default: 30s) */
  flushIntervalMs?: number;
  /** Max events per batch (default: 50) */
  maxBatchSize?: number;
}

/**
 * AIM Server Reporter — batch POST audit events to a central server.
 * Includes offline queue: events are persisted to disk and flushed on reconnect.
 */
export class AIMServerReporter {
  private readonly serverUrl: string;
  private readonly agentId: string;
  private readonly dataDir: string;
  private readonly apiToken: string;
  private readonly maxBatchSize: number;
  private readonly flushIntervalMs: number;

  private queue: AuditEvent[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;

  constructor(options: ReporterOptions) {
    this.serverUrl = options.serverUrl.replace(/\/$/, '');
    this.agentId = options.agentId;
    this.dataDir = options.dataDir;
    this.apiToken = options.apiToken ?? '';
    this.maxBatchSize = options.maxBatchSize ?? MAX_BATCH_SIZE;
    this.flushIntervalMs = options.flushIntervalMs ?? FLUSH_INTERVAL_MS;

    // Load any persisted queue
    this.loadQueue();
  }

  /** Enqueue an event for reporting. Persists to disk for offline resilience. */
  enqueue(event: AuditEvent): void {
    this.queue.push(event);

    // Trim queue if it exceeds max size (drop oldest)
    if (this.queue.length > MAX_QUEUE_SIZE) {
      this.queue = this.queue.slice(-MAX_QUEUE_SIZE);
    }

    this.persistQueue();

    // Auto-flush when batch is full
    if (this.queue.length >= this.maxBatchSize) {
      void this.flush();
    }
  }

  /** Start the periodic flush timer */
  start(): void {
    if (this.flushTimer) return;
    this.flushTimer = setInterval(() => {
      void this.flush();
    }, this.flushIntervalMs);

    // Initial flush for any queued events
    if (this.queue.length > 0) {
      void this.flush();
    }
  }

  /** Stop the periodic flush timer and flush remaining events */
  async stop(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  /** Flush queued events to the server in batches */
  async flush(): Promise<{ sent: number; failed: number; queued: number }> {
    if (this.flushing || this.queue.length === 0) {
      return { sent: 0, failed: 0, queued: this.queue.length };
    }

    this.flushing = true;
    let sent = 0;
    let failed = 0;

    try {
      while (this.queue.length > 0) {
        const batch = this.queue.slice(0, this.maxBatchSize);

        try {
          await this.postBatch(batch);
          // Remove sent events from queue
          this.queue = this.queue.slice(batch.length);
          sent += batch.length;
        } catch {
          // Server unreachable — keep in queue for retry
          failed += batch.length;
          break;
        }
      }

      this.persistQueue();
    } finally {
      this.flushing = false;
    }

    return { sent, failed, queued: this.queue.length };
  }

  /** Get current queue length */
  getQueueLength(): number {
    return this.queue.length;
  }

  private async postBatch(events: AuditEvent[]): Promise<void> {
    const body = JSON.stringify({
      agentId: this.agentId,
      events,
    });

    return new Promise((resolve, reject) => {
      const url = new URL('/v1/audit/events', this.serverUrl);
      const isHttps = url.protocol === 'https:';
      const mod = isHttps ? https : http;

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Content-Length': String(Buffer.byteLength(body)),
        'User-Agent': 'aim-core/reporter',
      };

      if (this.apiToken) {
        headers['Authorization'] = `Bearer ${this.apiToken}`;
      }

      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers,
        timeout: 10000,
      };

      const req = mod.request(options, (res) => {
        let data = '';
        res.on('data', (chunk: Buffer | string) => { data += chunk; });
        res.on('end', () => {
          if (res.statusCode && res.statusCode < 400) {
            resolve();
          } else {
            reject(new Error(`Server returned ${res.statusCode}: ${data.slice(0, 200)}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
      req.write(body);
      req.end();
    });
  }

  private persistQueue(): void {
    try {
      fs.mkdirSync(this.dataDir, { recursive: true });
      const queuePath = path.join(this.dataDir, QUEUE_FILE);
      const content = this.queue.map((e) => JSON.stringify(e)).join('\n');
      fs.writeFileSync(queuePath, content + (content ? '\n' : ''), 'utf-8');
    } catch {
      // Persistence is best-effort
    }
  }

  private loadQueue(): void {
    try {
      const queuePath = path.join(this.dataDir, QUEUE_FILE);
      if (!fs.existsSync(queuePath)) return;

      const content = fs.readFileSync(queuePath, 'utf-8').trim();
      if (!content) return;

      const lines = content.split('\n').filter(Boolean);
      this.queue = lines.map((line) => JSON.parse(line) as AuditEvent);
    } catch {
      this.queue = [];
    }
  }
}
