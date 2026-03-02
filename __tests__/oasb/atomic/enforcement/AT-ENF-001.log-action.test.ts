// AT-ENF-001: Log Enforcement Action
// Tests that 'log' action records event without process manipulation.
// Verifies the simplest enforcement path: event in, log result out.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';
import type { ARPEvent } from '../../../src/arp';

describe('AT-ENF-001: Log Enforcement Action', () => {
  let arp: ArpWrapper;

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
      rules: [
        {
          name: 'log-rule',
          condition: { category: 'anomaly' },
          action: 'log',
        },
      ],
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should return success when executing log action', async () => {
    const mockEvent: ARPEvent = {
      id: 'test-enf-001-1',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'anomaly',
      severity: 'medium',
      description: 'Anomalous process behavior detected',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('log', mockEvent);

    expect(result.action).toBe('log');
    expect(result.success).toBe(true);
    expect(result.event).toBe(mockEvent);
  });

  it('should not set a targetPid for log actions', async () => {
    const mockEvent: ARPEvent = {
      id: 'test-enf-001-2',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'anomaly',
      severity: 'high',
      description: 'Suspicious activity logged',
      data: { pid: 99999 },
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('log', mockEvent);

    expect(result.action).toBe('log');
    expect(result.success).toBe(true);
    expect(result.targetPid).toBeUndefined();
  });

  it('should include a reason string in the result', async () => {
    const mockEvent: ARPEvent = {
      id: 'test-enf-001-3',
      timestamp: new Date().toISOString(),
      source: 'network',
      category: 'anomaly',
      severity: 'low',
      description: 'Unexpected outbound connection',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const enforcement = arp.getEnforcement();
    const result = await enforcement.execute('log', mockEvent);

    expect(result.reason).toBeDefined();
    expect(typeof result.reason).toBe('string');
    expect(result.reason.length).toBeGreaterThan(0);
  });
});
