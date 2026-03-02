// INT-008: Kill Switch and Recovery
// ATLAS: AML.TA0006 (ML Attack Lifecycle)
// OWASP: A04 (Excessive Agency)
// Scenario: Critical threat triggers kill, verify process stops, then recovery
//
// This test spawns a real child process, uses ARP's enforcement engine
// to kill it, and verifies:
// 1. The kill action succeeds and the process terminates
// 2. ARP itself remains running and can process new events after the kill
// 3. The enforcement result contains correct metadata

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';
import type { ARPEvent, AlertRule } from '../../../src/arp';

describe('INT-008: Kill Switch and Recovery', () => {
  let arp: ArpWrapper;
  let childProcess: ChildProcess | null = null;

  const killRules: AlertRule[] = [
    {
      name: 'critical-threat-kill',
      condition: { category: 'threat', minSeverity: 'critical' },
      action: 'kill',
    },
    {
      name: 'high-violation-alert',
      condition: { category: 'violation', minSeverity: 'high' },
      action: 'alert',
    },
  ];

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
      rules: killRules,
    });
    await arp.start();
  });

  afterEach(async () => {
    // Clean up child process if still running
    if (childProcess && childProcess.pid) {
      try {
        process.kill(childProcess.pid, 0); // Check if alive
        childProcess.kill('SIGKILL');
      } catch {
        // Already dead
      }
    }
    childProcess = null;
    await arp.stop();
  });

  /**
   * Spawn a simple long-running child process for testing.
   * Uses 'sleep' on unix which blocks indefinitely.
   */
  function spawnTarget(): ChildProcess {
    const child = spawn('sleep', ['300'], {
      stdio: 'ignore',
      detached: false,
    });
    childProcess = child;
    return child;
  }

  /**
   * Check if a process with the given PID is alive.
   */
  function isProcessAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Wait for a process to terminate (with timeout).
   */
  function waitForProcessExit(pid: number, timeoutMs: number = 5000): Promise<boolean> {
    return new Promise((resolve) => {
      const deadline = Date.now() + timeoutMs;
      const check = () => {
        if (!isProcessAlive(pid)) {
          resolve(true);
          return;
        }
        if (Date.now() > deadline) {
          resolve(false);
          return;
        }
        setTimeout(check, 100);
      };
      check();
    });
  }

  it('should kill a real child process via enforcement engine', async () => {
    const child = spawnTarget();
    const pid = child.pid!;

    // Verify child is alive
    expect(isProcessAlive(pid)).toBe(true);

    // Create a mock event referencing the child PID
    const mockEvent: ARPEvent = {
      id: 'kill-test-001',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Critical threat: malicious process detected',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    // Execute kill action via enforcement engine
    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('kill', mockEvent, pid);

    expect(result.action).toBe('kill');
    expect(result.success).toBe(true);
    expect(result.targetPid).toBe(pid);
    expect(result.reason).toContain(`Killed PID ${pid}`);

    // Wait for process to actually terminate
    const exited = await waitForProcessExit(pid);
    expect(exited).toBe(true);

    // Process should be dead now
    expect(isProcessAlive(pid)).toBe(false);
  });

  it('should report failure when trying to kill a non-existent PID', async () => {
    // Use a PID that almost certainly does not exist
    const fakePid = 999999;

    const mockEvent: ARPEvent = {
      id: 'kill-test-002',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Kill attempt on non-existent process',
      data: { pid: fakePid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('kill', mockEvent, fakePid);

    expect(result.action).toBe('kill');
    expect(result.success).toBe(false);
    expect(result.targetPid).toBe(fakePid);
    expect(result.reason).toContain('Failed to kill');
  });

  it('should report failure when no PID is provided for kill', async () => {
    const mockEvent: ARPEvent = {
      id: 'kill-test-003',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Kill attempt without PID',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('kill', mockEvent);

    expect(result.action).toBe('kill');
    expect(result.success).toBe(false);
    expect(result.reason).toContain('No PID');
  });

  it('should continue processing events after killing a process', async () => {
    const child = spawnTarget();
    const pid = child.pid!;

    // Kill the child
    const mockEvent: ARPEvent = {
      id: 'kill-test-004',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Kill target process',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const killResult = await enforcement.execute('kill', mockEvent, pid);
    expect(killResult.success).toBe(true);

    // Wait for termination
    await waitForProcessExit(pid);

    // ARP should still be operational — inject new events
    await arp.injectEvent({
      source: 'network',
      category: 'normal',
      severity: 'info',
      description: 'Post-kill normal event: ARP still running',
      data: { phase: 'recovery', eventAfterKill: true },
    });

    await arp.injectEvent({
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Post-kill violation: new threat detected',
      data: { phase: 'recovery', newThreat: true },
    });

    // Verify events were captured after the kill
    const allEvents = arp.collector.getEvents();
    expect(allEvents.length).toBe(2);

    const normalEvents = arp.collector.eventsByCategory('normal');
    expect(normalEvents.length).toBe(1);
    expect(normalEvents[0].data.eventAfterKill).toBe(true);

    const violations = arp.collector.eventsByCategory('violation');
    expect(violations.length).toBe(1);
    expect(violations[0].data.newThreat).toBe(true);

    // Enforcement still works after kill
    const alertActions = arp.collector.enforcementsByAction('alert');
    expect(alertActions.length).toBe(1);
  });

  it('should handle kill triggered by L0 rule via event injection', async () => {
    const child = spawnTarget();
    const pid = child.pid!;

    expect(isProcessAlive(pid)).toBe(true);

    // Inject a critical threat event with the child PID in data
    // The kill rule should fire, but note: L0 rule enforcement
    // calls execute() which looks for data.pid
    await arp.injectEvent({
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Critical process threat detected',
      data: { pid },
    });

    // Verify the threat was captured
    const threats = arp.collector.eventsByCategory('threat');
    expect(threats.length).toBe(1);

    // Verify kill enforcement was triggered by the rule
    const killActions = arp.collector.enforcementsByAction('kill');
    expect(killActions.length).toBe(1);
    expect(killActions[0].reason).toContain('critical-threat-kill');

    // Wait for the process to terminate (enforcement engine sends SIGTERM)
    const exited = await waitForProcessExit(pid, 8000);
    expect(exited).toBe(true);
  });

  it('should verify ARP instance itself survives process kill', async () => {
    const child = spawnTarget();
    const pid = child.pid!;

    // Kill the child via enforcement
    const mockEvent: ARPEvent = {
      id: 'kill-test-006',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Verify ARP survives kill',
      data: { pid },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    await enforcement.execute('kill', mockEvent, pid);
    await waitForProcessExit(pid);

    // ARP's underlying instance should still be accessible
    const instance = arp.getInstance();
    expect(instance).toBeDefined();
    expect(instance.isRunning()).toBe(true);

    // Engine should still accept events
    const engine = arp.getEngine();
    const newEvent = await engine.emit({
      source: 'heartbeat',
      category: 'normal',
      severity: 'info',
      description: 'ARP heartbeat after kill — system operational',
      data: { systemCheck: true },
    });

    expect(newEvent.id).toBeDefined();
    expect(newEvent.timestamp).toBeDefined();
    expect(newEvent.classifiedBy).toBe('L0-rules');

    // Collector should capture the heartbeat
    const heartbeats = arp.collector.eventsBySource('heartbeat');
    expect(heartbeats.length).toBe(1);
    expect(heartbeats[0].data.systemCheck).toBe(true);
  });
});
