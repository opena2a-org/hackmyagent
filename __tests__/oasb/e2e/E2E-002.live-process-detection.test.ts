// E2E-002: Live Process Detection
// Proves ARP's ProcessMonitor detects real child processes via `ps` polling.
// No event injection — the monitor polls the OS process table directly.
//
// ATLAS: AML.T0046
// OWASP: A04

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';

describe('E2E-002: Live Process Detection', () => {
  let arp: ArpWrapper;
  const children: ChildProcess[] = [];

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: {
        process: true,
        network: false,
        filesystem: false,
      },
      processIntervalMs: 500, // Fast polling for test
    });
    await arp.start();

    // Let the initial snapshot complete
    await new Promise((r) => setTimeout(r, 600));
  });

  afterEach(async () => {
    // Kill any spawned children
    for (const child of children) {
      try {
        child.kill('SIGKILL');
      } catch {
        // already dead
      }
    }
    children.length = 0;
    await arp.stop();
  });

  it('should detect a new child process spawned after ARP starts', async () => {
    // Spawn a real long-running child process
    const child = spawn('sleep', ['30'], { stdio: 'ignore' });
    children.push(child);

    // Wait for the process monitor to detect the new child
    const event = await arp.waitForEvent(
      (e) => e.source === 'process' && e.data.pid === child.pid,
      10000,
    );

    expect(event).toBeDefined();
    expect(event.source).toBe('process');
    expect(event.data.pid).toBe(child.pid);
  });

  it('should detect a suspicious binary (curl) as a violation', async () => {
    // Spawn curl against a non-routable TEST-NET address — it stays alive trying to connect
    const child = spawn('curl', ['-s', '--connect-timeout', '30', 'http://192.0.2.1/'], {
      stdio: 'ignore',
    });
    children.push(child);

    // Wait for the suspicious binary detection
    const event = await arp.waitForEvent(
      (e) =>
        e.source === 'process' &&
        e.category === 'violation' &&
        e.data.binary === 'curl',
      10000,
    );

    expect(event).toBeDefined();
    expect(event.category).toBe('violation');
    expect(event.severity).toBe('high');
    expect(event.data.binary).toBe('curl');
    expect(event.data.pid).toBe(child.pid);
  });

  it('should detect process termination', async () => {
    // Spawn a short-lived process
    const child = spawn('sleep', ['1'], { stdio: 'ignore' });
    children.push(child);

    // Wait for the initial detection
    await arp.waitForEvent(
      (e) => e.source === 'process' && e.data.pid === child.pid,
      10000,
    );

    // Now wait for the termination event (sleep 1 ends after 1s)
    const termEvent = await arp.waitForEvent(
      (e) =>
        e.source === 'process' &&
        e.data.pid === child.pid &&
        e.data.action === 'terminated',
      10000,
    );

    expect(termEvent).toBeDefined();
    expect(termEvent.data.action).toBe('terminated');
  });
});
