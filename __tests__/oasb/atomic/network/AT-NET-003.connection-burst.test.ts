// AT-NET-003: Connection Burst Detection
// ATLAS: AML.T0029 (Denial of Service)
// OWASP: A06 (Excessive Consumption)

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';

describe('AT-NET-003: Connection Burst Detection', () => {
  let arp: ArpWrapper;

  const BURST_COUNT = 15;

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { network: false },
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should capture all events from a rapid connection burst', async () => {
    for (let i = 0; i < BURST_COUNT; i++) {
      await arp.injectEvent({
        source: 'network-monitor',
        category: 'anomaly',
        severity: 'warning',
        description: `Rapid connection burst event ${i + 1}/${BURST_COUNT}`,
        data: {
          remoteAddr: `target-${i}.example.com`,
          remotePort: 443,
          protocol: 'tcp',
          direction: 'outbound',
          burstIndex: i,
        },
      });
    }

    const allEvents = arp.collector.getEvents();
    expect(allEvents.length).toBe(BURST_COUNT);
  });

  it('should categorize all burst events as anomalies', async () => {
    for (let i = 0; i < BURST_COUNT; i++) {
      await arp.injectEvent({
        source: 'network-monitor',
        category: 'anomaly',
        severity: 'warning',
        description: `Rapid connection burst event ${i + 1}/${BURST_COUNT}`,
        data: {
          remoteAddr: `target-${i}.example.com`,
          remotePort: 443,
          protocol: 'tcp',
          direction: 'outbound',
          burstIndex: i,
        },
      });
    }

    const anomalies = arp.collector.eventsByCategory('anomaly');
    expect(anomalies.length).toBe(BURST_COUNT);

    const warnings = arp.collector.eventsBySeverity('warning');
    expect(warnings.length).toBe(BURST_COUNT);
  });

  it('should preserve event ordering within a burst', async () => {
    for (let i = 0; i < BURST_COUNT; i++) {
      await arp.injectEvent({
        source: 'network-monitor',
        category: 'anomaly',
        severity: 'warning',
        description: `Rapid connection burst event ${i + 1}/${BURST_COUNT}`,
        data: {
          remoteAddr: `target-${i}.example.com`,
          remotePort: 443,
          protocol: 'tcp',
          direction: 'outbound',
          burstIndex: i,
        },
      });
    }

    const events = arp.collector.getEvents();
    for (let i = 0; i < BURST_COUNT; i++) {
      expect(events[i].data.burstIndex).toBe(i);
    }
  });
});
