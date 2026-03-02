// AT-ENF-005: Process Resume via SIGCONT
// Tests enforcement engine's ability to resume a previously paused process.
// Pauses a real child process, then resumes it via SIGCONT,
// verifying it is removed from the paused PID tracking list.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';
import type { ARPEvent } from '../../../src/arp';

describe('AT-ENF-005: Process Resume via SIGCONT', () => {
  let arp: ArpWrapper;
  let child: ChildProcess | null = null;

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
    });
    await arp.start();
  });

  afterEach(async () => {
    if (child && child.pid) {
      // Ensure the process is resumed before killing, to avoid orphaned stopped processes
      try {
        arp.getEnforcement().resume(child.pid);
      } catch { /* already resumed or dead */ }
      try {
        process.kill(child.pid, 'SIGKILL');
      } catch { /* already dead */ }
      child = null;
    }
    await arp.stop();
  });

  it('should resume a paused process and remove it from paused list', async () => {
    child = spawn('node', ['-e', 'setTimeout(()=>{},30000)'], {
      stdio: 'ignore',
      detached: false,
    });
    const pid = child.pid!;
    expect(pid).toBeDefined();

    const mockEvent: ARPEvent = {
      id: 'test-enf-005-1',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Process paused for investigation',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();

    // Pause the process first
    const pauseResult = await enforcement.execute('pause', mockEvent, pid);
    expect(pauseResult.success).toBe(true);
    expect(enforcement.getPausedPids()).toContain(pid);

    // Resume the process
    const resumed = enforcement.resume(pid);
    expect(resumed).toBe(true);
    expect(enforcement.getPausedPids()).not.toContain(pid);
    expect(enforcement.getPausedPids()).toHaveLength(0);
  }, 10000);

  it('should return false when resuming a PID that was never paused', () => {
    const enforcement = arp.getEnforcement();
    const result = enforcement.resume(999999);

    expect(result).toBe(false);
    expect(enforcement.getPausedPids()).toHaveLength(0);
  });

  it('should handle resuming the same PID twice gracefully', async () => {
    child = spawn('node', ['-e', 'setTimeout(()=>{},30000)'], {
      stdio: 'ignore',
      detached: false,
    });
    const pid = child.pid!;
    expect(pid).toBeDefined();

    const mockEvent: ARPEvent = {
      id: 'test-enf-005-3',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Process paused then double-resumed',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();

    // Pause, then resume twice
    await enforcement.execute('pause', mockEvent, pid);
    expect(enforcement.getPausedPids()).toContain(pid);

    const firstResume = enforcement.resume(pid);
    expect(firstResume).toBe(true);
    expect(enforcement.getPausedPids()).not.toContain(pid);

    // Second resume should return false (no longer in paused set)
    const secondResume = enforcement.resume(pid);
    expect(secondResume).toBe(false);
  }, 10000);

  it('should allow pausing and resuming multiple processes independently', async () => {
    const children: ChildProcess[] = [];

    // Spawn two child processes
    for (let i = 0; i < 2; i++) {
      const c = spawn('node', ['-e', 'setTimeout(()=>{},30000)'], {
        stdio: 'ignore',
        detached: false,
      });
      children.push(c);
    }

    const pid1 = children[0].pid!;
    const pid2 = children[1].pid!;
    expect(pid1).toBeDefined();
    expect(pid2).toBeDefined();

    const enforcement = arp.getEnforcement();

    const makeEvent = (id: string, pid: number): ARPEvent => ({
      id,
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: `Process ${pid} paused`,
      data: { pid },
      classifiedBy: 'L0-rules',
    });

    // Pause both
    await enforcement.execute('pause', makeEvent('test-enf-005-4a', pid1), pid1);
    await enforcement.execute('pause', makeEvent('test-enf-005-4b', pid2), pid2);
    expect(enforcement.getPausedPids()).toContain(pid1);
    expect(enforcement.getPausedPids()).toContain(pid2);
    expect(enforcement.getPausedPids()).toHaveLength(2);

    // Resume only the first
    enforcement.resume(pid1);
    expect(enforcement.getPausedPids()).not.toContain(pid1);
    expect(enforcement.getPausedPids()).toContain(pid2);
    expect(enforcement.getPausedPids()).toHaveLength(1);

    // Resume the second
    enforcement.resume(pid2);
    expect(enforcement.getPausedPids()).toHaveLength(0);

    // Clean up both children
    for (const c of children) {
      try { process.kill(c.pid!, 'SIGKILL'); } catch { /* already dead */ }
    }
    child = null; // Prevent afterEach from trying to clean up
  }, 10000);
});
