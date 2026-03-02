// INT-005: Baseline Learning Then Attack Burst
// ATLAS: AML.T0015 (Evasion via Slow Poisoning)
// OWASP: A04 (Excessive Agency)
// Scenario: 5 minutes of normal traffic, then sudden attack burst
//
// This test simulates an attack pattern where the adversary establishes
// normal-looking traffic first (30 info events), then launches a rapid
// burst of 5 high-severity violation events. The event engine's buffer
// should retain both phases, allowing detection of the severity shift.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';
import type { AlertRule } from '../../../src/arp';

describe('INT-005: Baseline Learning Then Attack Burst', () => {
  let arp: ArpWrapper;

  const burstRules: AlertRule[] = [
    {
      name: 'violation-alert',
      condition: { category: 'violation', minSeverity: 'high' },
      action: 'alert',
    },
    {
      name: 'threat-kill',
      condition: { category: 'threat', minSeverity: 'critical' },
      action: 'kill',
    },
  ];

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
      rules: burstRules,
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should accept 30 normal baseline events without enforcement', async () => {
    for (let i = 0; i < 30; i++) {
      await arp.injectEvent({
        source: 'network',
        category: 'normal',
        severity: 'info',
        description: `Steady baseline traffic #${i + 1}`,
        data: {
          remoteAddr: 'api.internal.com',
          remotePort: 443,
          protocol: 'tcp',
          direction: 'outbound',
          sequence: i + 1,
          phase: 'baseline',
        },
      });
    }

    const normalEvents = arp.collector.eventsByCategory('normal');
    expect(normalEvents.length).toBe(30);

    const enforcements = arp.collector.getEnforcements();
    expect(enforcements.length).toBe(0);
  });

  it('should detect violation burst after baseline phase', async () => {
    // Phase 1: Baseline (30 normal events)
    for (let i = 0; i < 30; i++) {
      await arp.injectEvent({
        source: 'process',
        category: 'normal',
        severity: 'info',
        description: `Normal process activity #${i + 1}`,
        data: { pid: 1000 + i, binary: 'node', phase: 'baseline' },
      });
    }

    // Phase 2: Attack burst (5 high-severity violations)
    for (let i = 0; i < 5; i++) {
      await arp.injectEvent({
        source: 'process',
        category: 'violation',
        severity: 'high',
        description: `Attack burst violation #${i + 1}`,
        data: {
          pid: 50000 + i,
          binary: ['curl', 'wget', 'nc', 'sh', 'python3'][i],
          command: `Malicious command #${i + 1}`,
          phase: 'attack',
        },
      });
    }

    const normalEvents = arp.collector.eventsByCategory('normal');
    expect(normalEvents.length).toBe(30);

    const violations = arp.collector.eventsByCategory('violation');
    expect(violations.length).toBe(5);

    // All violations should trigger alert enforcement
    const alertActions = arp.collector.enforcementsByAction('alert');
    expect(alertActions.length).toBe(5);
  });

  it('should retain both baseline and attack events in engine buffer', async () => {
    // Inject baseline
    for (let i = 0; i < 30; i++) {
      await arp.injectEvent({
        source: 'network',
        category: 'normal',
        severity: 'info',
        description: `Baseline #${i + 1}`,
        data: { sequence: i + 1, phase: 'baseline' },
      });
    }

    // Inject attack burst
    for (let i = 0; i < 5; i++) {
      await arp.injectEvent({
        source: 'network',
        category: 'violation',
        severity: 'high',
        description: `Attack #${i + 1}`,
        data: { sequence: 30 + i + 1, phase: 'attack' },
      });
    }

    // Use getRecentEvents to verify the engine buffer contains all events
    const recentEvents = arp.getEngine().getRecentEvents(300000); // 5 minute window
    expect(recentEvents.length).toBe(35);

    // Verify event ordering: baseline first, then attack
    const baselineInBuffer = recentEvents.filter((e) => e.data.phase === 'baseline');
    const attackInBuffer = recentEvents.filter((e) => e.data.phase === 'attack');
    expect(baselineInBuffer.length).toBe(30);
    expect(attackInBuffer.length).toBe(5);
  });

  it('should show attack burst events have higher severity than baseline', async () => {
    const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];

    // Baseline with info severity
    for (let i = 0; i < 10; i++) {
      await arp.injectEvent({
        source: 'process',
        category: 'normal',
        severity: 'info',
        description: `Baseline event #${i + 1}`,
        data: { phase: 'baseline' },
      });
    }

    // Attack burst with escalating severity
    const attackSeverities: Array<'medium' | 'high' | 'high' | 'critical' | 'critical'> = [
      'medium', 'high', 'high', 'high', 'high',
    ];

    for (let i = 0; i < attackSeverities.length; i++) {
      await arp.injectEvent({
        source: 'process',
        category: 'violation',
        severity: attackSeverities[i],
        description: `Attack event #${i + 1}`,
        data: { phase: 'attack' },
      });
    }

    const allEvents = arp.collector.getEvents();
    const baselineEvents = allEvents.filter((e) => e.data.phase === 'baseline');
    const attackEvents = allEvents.filter((e) => e.data.phase === 'attack');

    // All baseline events should be info severity
    for (const event of baselineEvents) {
      expect(event.severity).toBe('info');
    }

    // All attack events should be medium or higher
    for (const event of attackEvents) {
      const severityIdx = severityOrder.indexOf(event.severity);
      expect(severityIdx).toBeGreaterThanOrEqual(severityOrder.indexOf('medium'));
    }

    // The max severity in attack phase should exceed max severity in baseline
    const maxBaselineSeverity = Math.max(
      ...baselineEvents.map((e) => severityOrder.indexOf(e.severity))
    );
    const maxAttackSeverity = Math.max(
      ...attackEvents.map((e) => severityOrder.indexOf(e.severity))
    );
    expect(maxAttackSeverity).toBeGreaterThan(maxBaselineSeverity);
  });

  it('should handle mixed event sources during attack burst', async () => {
    // Baseline: single-source normal traffic
    for (let i = 0; i < 15; i++) {
      await arp.injectEvent({
        source: 'network',
        category: 'normal',
        severity: 'info',
        description: `Single-source baseline #${i + 1}`,
        data: { phase: 'baseline' },
      });
    }

    // Attack burst: multi-source violations
    const attackEvents = [
      { source: 'process' as const, binary: 'curl', description: 'Process: curl exfiltration' },
      { source: 'filesystem' as const, binary: undefined, description: 'Filesystem: /etc/passwd read' },
      { source: 'network' as const, binary: undefined, description: 'Network: connection to pastebin.com' },
      { source: 'process' as const, binary: 'nc', description: 'Process: netcat reverse shell' },
      { source: 'filesystem' as const, binary: undefined, description: 'Filesystem: .env file read' },
    ];

    for (const attack of attackEvents) {
      await arp.injectEvent({
        source: attack.source,
        category: 'violation',
        severity: 'high',
        description: attack.description,
        data: { phase: 'attack', binary: attack.binary },
      });
    }

    // Verify multi-source detection
    const processViolations = arp.collector.eventsBySource('process').filter((e) => e.category === 'violation');
    const filesystemViolations = arp.collector.eventsBySource('filesystem').filter((e) => e.category === 'violation');
    const networkViolations = arp.collector.eventsBySource('network').filter((e) => e.category === 'violation');

    expect(processViolations.length).toBe(2);
    expect(filesystemViolations.length).toBe(2);
    expect(networkViolations.length).toBe(1);

    // All attack violations should trigger enforcement
    const alertActions = arp.collector.enforcementsByAction('alert');
    expect(alertActions.length).toBe(5);
  });
});
