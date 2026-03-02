// AT-ENF-004: Process Kill via SIGTERM
// Tests enforcement engine's ability to terminate a running process.
// Spawns a real child process, sends SIGTERM via the enforcement engine,
// then verifies the process is no longer alive.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';
import type { ARPEvent } from '../../../src/arp';

/** Wait for a specified number of milliseconds */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Check if a process is still alive */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe('AT-ENF-004: Process Kill via SIGTERM', () => {
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
      try {
        process.kill(child.pid, 'SIGKILL');
      } catch { /* already dead */ }
      child = null;
    }
    await arp.stop();
  });

  it('should kill a running process and return success', async () => {
    child = spawn('node', ['-e', 'setTimeout(()=>{},30000)'], {
      stdio: 'ignore',
      detached: false,
    });
    const pid = child.pid!;
    expect(pid).toBeDefined();
    expect(isProcessAlive(pid)).toBe(true);

    const mockEvent: ARPEvent = {
      id: 'test-enf-004-1',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Malicious process detected — terminating',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('kill', mockEvent, pid);

    expect(result.action).toBe('kill');
    expect(result.success).toBe(true);
    expect(result.targetPid).toBe(pid);

    // Wait for SIGTERM to take effect
    await sleep(2000);

    expect(isProcessAlive(pid)).toBe(false);
  }, 10000);

  it('should fail to kill when no PID is provided', async () => {
    const mockEvent: ARPEvent = {
      id: 'test-enf-004-2',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'No PID available for kill',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('kill', mockEvent);

    expect(result.action).toBe('kill');
    expect(result.success).toBe(false);
    expect(result.reason).toContain('No PID');
  });

  it('should fail to kill a non-existent process', async () => {
    const fakePid = 999999;
    const mockEvent: ARPEvent = {
      id: 'test-enf-004-3',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Attempt to kill non-existent process',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('kill', mockEvent, fakePid);

    expect(result.action).toBe('kill');
    expect(result.success).toBe(false);
  });

  it('should remove a killed PID from paused list if it was paused', async () => {
    child = spawn('node', ['-e', 'setTimeout(()=>{},30000)'], {
      stdio: 'ignore',
      detached: false,
    });
    const pid = child.pid!;
    expect(pid).toBeDefined();

    const mockEvent: ARPEvent = {
      id: 'test-enf-004-4',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Paused process escalated to kill',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();

    // First pause it
    await enforcement.execute('pause', mockEvent, pid);
    expect(enforcement.getPausedPids()).toContain(pid);

    // Then kill it
    const result = await enforcement.execute('kill', mockEvent, pid);
    expect(result.success).toBe(true);
    expect(enforcement.getPausedPids()).not.toContain(pid);

    await sleep(1000);
    expect(isProcessAlive(pid)).toBe(false);
  }, 10000);
});
