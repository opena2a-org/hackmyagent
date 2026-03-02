// AT-INT-001: L0 Rule-Based Classification
// ATLAS: AML.T0054 (LLM Jailbreak)
// OWASP: A01 (Prompt Injection)
//
// Verifies that the event engine evaluates custom AlertRules and dispatches
// the correct enforcement actions (kill, alert) based on category and severity.
// Also verifies that benign events matching no rule produce no enforcement.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { AlertRule } from '../../../src/arp';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';

describe('AT-INT-001: L0 Rule-Based Classification', () => {
  let arp: ArpWrapper;

  const testRules: AlertRule[] = [
    {
      name: 'test-threat',
      condition: { category: 'threat', minSeverity: 'critical' },
      action: 'kill',
    },
    {
      name: 'test-violation',
      condition: { category: 'violation', minSeverity: 'high' },
      action: 'alert',
    },
  ];

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
      rules: testRules,
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should trigger kill enforcement for critical threat events', async () => {
    await arp.injectEvent({
      source: 'process',
      category: 'threat',
      severity: 'critical',
      description: 'Malicious prompt injection detected',
      data: { payload: 'ignore previous instructions' },
    });

    const enforcements = arp.collector.getEnforcements();
    expect(enforcements.length).toBeGreaterThanOrEqual(1);

    const killActions = arp.collector.enforcementsByAction('kill');
    expect(killActions.length).toBe(1);
    expect(killActions[0].action).toBe('kill');
    expect(killActions[0].reason).toContain('test-threat');
  });

  it('should trigger alert enforcement for high violation events', async () => {
    await arp.injectEvent({
      source: 'filesystem',
      category: 'violation',
      severity: 'high',
      description: 'Unauthorized access to sensitive file',
      data: { path: '/etc/shadow' },
    });

    const enforcements = arp.collector.getEnforcements();
    expect(enforcements.length).toBeGreaterThanOrEqual(1);

    const alertActions = arp.collector.enforcementsByAction('alert');
    expect(alertActions.length).toBe(1);
    expect(alertActions[0].action).toBe('alert');
    expect(alertActions[0].reason).toContain('test-violation');
  });

  it('should not trigger any enforcement for normal info events', async () => {
    await arp.injectEvent({
      source: 'network',
      category: 'normal',
      severity: 'info',
      description: 'Routine health check',
      data: { status: 'ok' },
    });

    const enforcements = arp.collector.getEnforcements();
    expect(enforcements.length).toBe(0);

    // The event itself should still be captured
    const events = arp.collector.eventsByCategory('normal');
    expect(events.length).toBe(1);
    expect(events[0].severity).toBe('info');
  });

  it('should not trigger kill for threat events below critical severity', async () => {
    await arp.injectEvent({
      source: 'process',
      category: 'threat',
      severity: 'high',
      description: 'Suspicious but not critical threat',
      data: { payload: 'borderline request' },
    });

    const killActions = arp.collector.enforcementsByAction('kill');
    expect(killActions.length).toBe(0);
  });
});
