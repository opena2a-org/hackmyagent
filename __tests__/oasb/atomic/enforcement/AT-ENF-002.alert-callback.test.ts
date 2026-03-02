// AT-ENF-002: Alert Callback Execution
// Tests the alert callback mechanism in EnforcementEngine.
// Verifies that registered callbacks fire on alert actions and
// that alerts succeed even without a callback registered.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';
import type { ARPEvent, EnforcementResult } from '../../../src/arp';

describe('AT-ENF-002: Alert Callback Execution', () => {
  let arp: ArpWrapper;

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should invoke the alert callback with event and result', async () => {
    const callbackFn = vi.fn();
    const enforcement = arp.getEnforcement();
    enforcement.setAlertCallback(callbackFn);

    const mockEvent: ARPEvent = {
      id: 'test-enf-002-1',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Unauthorized process spawn',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const result = await enforcement.execute('alert', mockEvent);

    expect(result.action).toBe('alert');
    expect(result.success).toBe(true);
    expect(callbackFn).toHaveBeenCalledOnce();
    expect(callbackFn).toHaveBeenCalledWith(mockEvent, expect.objectContaining({
      action: 'alert',
      success: true,
    }));
  });

  it('should succeed without a callback registered', async () => {
    const enforcement = arp.getEnforcement();
    // No callback set

    const mockEvent: ARPEvent = {
      id: 'test-enf-002-2',
      timestamp: new Date().toISOString(),
      source: 'network',
      category: 'anomaly',
      severity: 'medium',
      description: 'Suspicious outbound connection',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const result = await enforcement.execute('alert', mockEvent);

    expect(result.action).toBe('alert');
    expect(result.success).toBe(true);
  });

  it('should succeed even if the callback throws an error', async () => {
    const enforcement = arp.getEnforcement();
    enforcement.setAlertCallback(() => {
      throw new Error('Callback failure');
    });

    const mockEvent: ARPEvent = {
      id: 'test-enf-002-3',
      timestamp: new Date().toISOString(),
      source: 'filesystem',
      category: 'threat',
      severity: 'critical',
      description: 'Credential file access attempt',
      data: {},
      classifiedBy: 'L0-rules',
    };

    const result = await enforcement.execute('alert', mockEvent);

    // Callback errors should not block enforcement
    expect(result.action).toBe('alert');
    expect(result.success).toBe(true);
  });

  it('should replace a previous callback when setAlertCallback is called again', async () => {
    const firstCallback = vi.fn();
    const secondCallback = vi.fn();
    const enforcement = arp.getEnforcement();

    enforcement.setAlertCallback(firstCallback);
    enforcement.setAlertCallback(secondCallback);

    const mockEvent: ARPEvent = {
      id: 'test-enf-002-4',
      timestamp: new Date().toISOString(),
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Process violation detected',
      data: {},
      classifiedBy: 'L0-rules',
    };

    await enforcement.execute('alert', mockEvent);

    expect(firstCallback).not.toHaveBeenCalled();
    expect(secondCallback).toHaveBeenCalledOnce();
  });
});
