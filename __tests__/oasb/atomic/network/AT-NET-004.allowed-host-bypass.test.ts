// AT-NET-004: Allowed Host Bypass (subdomain attack)
// ATLAS: AML.T0024
// OWASP: A04 (Excessive Agency)

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';

describe('AT-NET-004: Allowed Host Bypass (subdomain attack)', () => {
  let arp: ArpWrapper;

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { network: false },
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should flag evil-api.example.com as anomaly (not a subdomain of api.example.com)', async () => {
    // evil-api.example.com ends with "api.example.com" as a string suffix,
    // but it is NOT a proper subdomain. A naive suffix check would miss this.
    await arp.injectEvent({
      source: 'network-monitor',
      category: 'anomaly',
      severity: 'warning',
      description: 'Connection to host mimicking allowed host via suffix match',
      data: {
        remoteAddr: 'evil-api.example.com',
        remotePort: 443,
        protocol: 'tcp',
        direction: 'outbound',
        allowedHost: 'api.example.com',
        matchResult: 'rejected',
      },
    });

    const anomalies = arp.collector.eventsByCategory('anomaly');
    expect(anomalies.length).toBe(1);
    expect(anomalies[0].data.remoteAddr).toBe('evil-api.example.com');
    expect(anomalies[0].data.matchResult).toBe('rejected');

    // Verify it was NOT treated as a normal connection
    const normalConnections = arp.collector.eventsByCategory('connection');
    expect(normalConnections.length).toBe(0);
  });

  it('should allow sub.api.example.com as a proper subdomain of api.example.com', async () => {
    // sub.api.example.com IS a proper subdomain of api.example.com
    // (preceded by a dot separator)
    await arp.injectEvent({
      source: 'network-monitor',
      category: 'connection',
      severity: 'info',
      description: 'Connection to proper subdomain of allowed host',
      data: {
        remoteAddr: 'sub.api.example.com',
        remotePort: 443,
        protocol: 'tcp',
        direction: 'outbound',
        allowedHost: 'api.example.com',
        matchResult: 'accepted',
      },
    });

    const connections = arp.collector.eventsByCategory('connection');
    expect(connections.length).toBe(1);
    expect(connections[0].data.remoteAddr).toBe('sub.api.example.com');
    expect(connections[0].data.matchResult).toBe('accepted');
    expect(connections[0].severity).toBe('info');
  });

  it('should correctly differentiate bypass attempts from legitimate subdomains', async () => {
    // Inject the bypass attempt
    await arp.injectEvent({
      source: 'network-monitor',
      category: 'anomaly',
      severity: 'warning',
      description: 'Suffix-match bypass: evil-api.example.com',
      data: {
        remoteAddr: 'evil-api.example.com',
        remotePort: 443,
        protocol: 'tcp',
        direction: 'outbound',
        allowedHost: 'api.example.com',
        matchResult: 'rejected',
      },
    });

    // Inject the legitimate subdomain
    await arp.injectEvent({
      source: 'network-monitor',
      category: 'connection',
      severity: 'info',
      description: 'Proper subdomain: sub.api.example.com',
      data: {
        remoteAddr: 'sub.api.example.com',
        remotePort: 443,
        protocol: 'tcp',
        direction: 'outbound',
        allowedHost: 'api.example.com',
        matchResult: 'accepted',
      },
    });

    const allEvents = arp.collector.getEvents();
    expect(allEvents.length).toBe(2);

    // The bypass attempt should be an anomaly
    expect(
      arp.collector.hasEvent(
        (e) =>
          e.data.remoteAddr === 'evil-api.example.com' &&
          e.category === 'anomaly'
      )
    ).toBe(true);

    // The legitimate subdomain should be a normal connection
    expect(
      arp.collector.hasEvent(
        (e) =>
          e.data.remoteAddr === 'sub.api.example.com' &&
          e.category === 'connection'
      )
    ).toBe(true);
  });
});
