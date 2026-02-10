import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AIMServerReporter } from './reporter';
import type { AuditEvent } from './types';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-reporter-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

function makeEvent(plugin: string, action: string): AuditEvent {
  return {
    timestamp: new Date().toISOString(),
    plugin,
    action,
    target: 'test-target',
    result: 'allowed',
  };
}

describe('AIMServerReporter', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('enqueues events', () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    reporter.enqueue(makeEvent('test', 'scan'));
    reporter.enqueue(makeEvent('test', 'fix'));

    expect(reporter.getQueueLength()).toBe(2);
  });

  it('persists queue to disk', () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    reporter.enqueue(makeEvent('test', 'persist'));

    const queuePath = path.join(dir, 'report-queue.jsonl');
    expect(fs.existsSync(queuePath)).toBe(true);

    const content = fs.readFileSync(queuePath, 'utf-8').trim();
    const parsed = JSON.parse(content);
    expect(parsed.plugin).toBe('test');
    expect(parsed.action).toBe('persist');
  });

  it('loads queue from disk on init', () => {
    // First reporter writes queue
    const reporter1 = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });
    reporter1.enqueue(makeEvent('test', 'queued'));

    // Second reporter should load it
    const reporter2 = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });
    expect(reporter2.getQueueLength()).toBe(1);
  });

  it('trims queue at max size', () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    // Enqueue more than MAX_QUEUE_SIZE (1000)
    for (let i = 0; i < 1010; i++) {
      reporter.enqueue(makeEvent('test', `action-${i}`));
    }

    expect(reporter.getQueueLength()).toBe(1000);
  });

  it('flush returns 0 sent when server unreachable', async () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://localhost:99999',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    reporter.enqueue(makeEvent('test', 'fail'));
    const result = await reporter.flush();

    expect(result.sent).toBe(0);
    expect(result.failed).toBeGreaterThan(0);
    expect(result.queued).toBeGreaterThan(0); // Still in queue for retry
  });

  it('flush with empty queue returns immediately', async () => {
    const reporter = new AIMServerReporter({
      serverUrl: 'https://aim.example.com',
      agentId: 'aim_test123',
      dataDir: dir,
    });

    const result = await reporter.flush();
    expect(result.sent).toBe(0);
    expect(result.failed).toBe(0);
    expect(result.queued).toBe(0);
  });
});
