// AT-PROC-005: Process Terminated Detection
// ATLAS: AML.TA0006 (ML Attack Lifecycle)
//
// Verifies that ARP captures process termination events and can detect
// rapid respawn patterns (terminated followed by immediate new child),
// which may indicate restart loops or persistent exploitation attempts.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';

describe('AT-PROC-005: Process Terminated Detection', () => {
  let arp: ArpWrapper;

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false },
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should capture a process termination event', async () => {
    await arp.injectEvent({
      source: 'process',
      category: 'normal',
      severity: 'info',
      description: 'Child process terminated: PID 50001',
      data: {
        pid: 50001,
        action: 'terminated',
      },
    });

    const events = arp.collector.getEvents();
    expect(events.length).toBe(1);
    expect(events[0].source).toBe('process');
    expect(events[0].category).toBe('normal');
    expect(events[0].data.action).toBe('terminated');
    expect(events[0].data.pid).toBe(50001);
  });

  it('should capture both terminated and respawned events in sequence', async () => {
    // Original process terminates
    await arp.injectEvent({
      source: 'process',
      category: 'normal',
      severity: 'info',
      description: 'Child process terminated: PID 50002',
      data: {
        pid: 50002,
        action: 'terminated',
      },
    });

    // Rapid respawn: new child process appears immediately after
    await arp.injectEvent({
      source: 'process',
      category: 'normal',
      severity: 'info',
      description: 'New child process: PID 50003 — node worker.js',
      data: {
        pid: 50003,
        command: 'node worker.js',
        user: 'agent',
        cpu: 5,
        mem: 2,
      },
    });

    const events = arp.collector.getEvents();
    expect(events.length).toBe(2);

    // First event: termination
    const terminated = events[0];
    expect(terminated.data.action).toBe('terminated');
    expect(terminated.data.pid).toBe(50002);

    // Second event: respawn
    const respawned = events[1];
    expect(respawned.data.pid).toBe(50003);
    expect(respawned.data.command).toBe('node worker.js');
  });

  it('should capture multiple rapid respawn cycles', async () => {
    // Simulate a restart loop: terminate -> spawn -> terminate -> spawn
    const cycle = [
      { pid: 50010, action: 'terminated', description: 'Child process terminated: PID 50010' },
      { pid: 50011, command: 'node crash-loop.js', description: 'New child process: PID 50011 — node crash-loop.js' },
      { pid: 50011, action: 'terminated', description: 'Child process terminated: PID 50011' },
      { pid: 50012, command: 'node crash-loop.js', description: 'New child process: PID 50012 — node crash-loop.js' },
    ];

    for (const step of cycle) {
      await arp.injectEvent({
        source: 'process',
        category: 'normal',
        severity: 'info',
        description: step.description,
        data: {
          pid: step.pid,
          ...(step.action ? { action: step.action } : {}),
          ...(step.command ? { command: step.command, user: 'agent', cpu: 3, mem: 1 } : {}),
        },
      });
    }

    const events = arp.collector.getEvents();
    expect(events.length).toBe(4);

    // Verify the alternating terminate/spawn pattern
    const terminated = events.filter((e) => e.data.action === 'terminated');
    expect(terminated.length).toBe(2);

    const spawned = events.filter((e) => e.data.command !== undefined);
    expect(spawned.length).toBe(2);

    // All should be from the process source
    for (const event of events) {
      expect(event.source).toBe('process');
      expect(event.category).toBe('normal');
    }
  });

  it('should use waitForEvent to detect a termination event', async () => {
    // Start waiting before injecting
    const waitPromise = arp.waitForEvent(
      (e) => e.source === 'process' && e.data.action === 'terminated',
      5000,
    );

    await arp.injectEvent({
      source: 'process',
      category: 'normal',
      severity: 'info',
      description: 'Child process terminated: PID 50020',
      data: {
        pid: 50020,
        action: 'terminated',
      },
    });

    const event = await waitPromise;
    expect(event).toBeDefined();
    expect(event.data.action).toBe('terminated');
    expect(event.data.pid).toBe(50020);
  });
});
