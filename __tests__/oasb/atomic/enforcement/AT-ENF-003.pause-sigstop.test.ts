// AT-ENF-003: Process Pause via SIGSTOP
// Tests enforcement engine's ability to pause a running process.
// Spawns a real child process and uses SIGSTOP to suspend it,
// then verifies the process appears in the paused PID list.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';
import type { ARPEvent } from '../../../src/arp';

describe('AT-ENF-003: Process Pause via SIGSTOP', () => {
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
      // Resume if paused, then kill
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

  it('should pause a running process and track its PID', async () => {
    child = spawn('node', ['-e', 'setTimeout(()=>{},30000)'], {
      stdio: 'ignore',
      detached: false,
    });
    const pid = child.pid!;
    expect(pid).toBeDefined();

    const mockEvent: ARPEvent = {
      id: 'test-enf-003-1',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Suspicious process activity',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('pause', mockEvent, pid);

    expect(result.action).toBe('pause');
    expect(result.success).toBe(true);
    expect(result.targetPid).toBe(pid);
    expect(enforcement.getPausedPids()).toContain(pid);
  }, 10000);

  it('should fail to pause when no PID is provided', async () => {
    const mockEvent: ARPEvent = {
      id: 'test-enf-003-2',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'No PID available',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('pause', mockEvent);

    expect(result.action).toBe('pause');
    expect(result.success).toBe(false);
    expect(result.reason).toContain('No PID');
  });

  it('should fail to pause a non-existent process', async () => {
    const fakePid = 999999;
    const mockEvent: ARPEvent = {
      id: 'test-enf-003-3',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Attempt to pause non-existent process',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('pause', mockEvent, fakePid);

    expect(result.action).toBe('pause');
    expect(result.success).toBe(false);
    expect(enforcement.getPausedPids()).not.toContain(fakePid);
  });
});
