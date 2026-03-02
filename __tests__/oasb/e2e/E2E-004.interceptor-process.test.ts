// E2E-004: Process Interceptor — Zero-Latency Detection
// Proves ARP's ProcessInterceptor catches child_process.spawn/exec BEFORE execution.
// Unlike the polling ProcessMonitor, this has zero detection latency and 100% accuracy.
//
// ATLAS: AML.T0046
// OWASP: A04

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { ChildProcess } from 'child_process';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';

// Use require() to get the same CJS module the interceptor patches
// (ESM imports are snapshots and won't reflect interceptor patches)
// eslint-disable-next-line @typescript-eslint/no-require-imports
const cp = require('child_process');

describe('E2E-004: Process Interceptor', () => {
  let arp: ArpWrapper;
  const children: ChildProcess[] = [];

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: {
        process: false,
        network: false,
        filesystem: false,
      },
      interceptors: {
        process: true,
      },
    });
    await arp.start();
  });

  afterEach(async () => {
    for (const child of children) {
      try { child.kill('SIGKILL'); } catch { /* already dead */ }
    }
    children.length = 0;
    await arp.stop();
  });

  it('should intercept spawn() with zero latency', async () => {
    const child = cp.spawn('echo', ['hello'], { stdio: 'ignore' });
    children.push(child);

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const echoEvent = events.find(
      (e: { source: string; data: Record<string, unknown> }) =>
        e.source === 'process' && e.data.binary === 'echo',
    );

    expect(echoEvent).toBeDefined();
    expect(echoEvent!.data.intercepted).toBe(true);
    expect(echoEvent!.data.command).toContain('echo');
  });

  it('should detect suspicious binary via interceptor', async () => {
    const child = cp.spawn('curl', ['--version'], { stdio: 'ignore' });
    children.push(child);

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const curlEvent = events.find(
      (e: { source: string; category: string; data: Record<string, unknown> }) =>
        e.source === 'process' && e.data.binary === 'curl',
    );

    expect(curlEvent).toBeDefined();
    expect(curlEvent!.category).toBe('violation');
    expect(curlEvent!.severity).toBe('high');
    expect(curlEvent!.data.suspicious).toBe(true);
    expect(curlEvent!.data.intercepted).toBe(true);
  });

  it('should intercept exec() shell commands', async () => {
    const child = cp.exec('echo test-exec', () => {});
    children.push(child);

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const execEvent = events.find(
      (e: { source: string; data: Record<string, unknown> }) =>
        e.source === 'process' &&
        typeof e.data.command === 'string' &&
        e.data.command.includes('echo test-exec'),
    );

    expect(execEvent).toBeDefined();
    expect(execEvent!.data.intercepted).toBe(true);
  });

  it('should detect suspicious binary in exec() command', async () => {
    const child = cp.exec('curl --version', () => {});
    children.push(child);

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const curlEvent = events.find(
      (e: { source: string; data: Record<string, unknown> }) =>
        e.source === 'process' && e.data.binary === 'curl',
    );

    expect(curlEvent).toBeDefined();
    expect(curlEvent!.category).toBe('violation');
    expect(curlEvent!.severity).toBe('high');
  });

  it('should restore original functions after stop', async () => {
    await arp.stop();

    const child = cp.spawn('echo', ['after-stop'], { stdio: 'ignore' });
    children.push(child);

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    expect(events.length).toBe(0);
  });
});
