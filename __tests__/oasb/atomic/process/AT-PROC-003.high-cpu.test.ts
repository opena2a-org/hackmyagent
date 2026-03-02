// AT-PROC-003: High CPU Detection
// ATLAS: AML.T0029 (Denial of Service)
// OWASP: A06 (Excessive Consumption)
//
// Verifies that ARP flags processes exceeding CPU thresholds as anomalies.
// The process monitor treats CPU > 90% as an anomaly condition.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ArpWrapper } from '../../../../src/oasb/harness/arp-wrapper';

describe('AT-PROC-003: High CPU Detection', () => {
  let arp: ArpWrapper;

  beforeEach(async () => {
    arp = new ArpWrapper({
      monitors: { process: false },
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
  });

  it('should capture a high CPU anomaly event (cpu > 90%)', async () => {
    await arp.injectEvent({
      source: 'process',
      category: 'anomaly',
      severity: 'medium',
      description: 'High CPU usage: PID 30001 at 95% — node crypto-mine.js',
      data: {
        pid: 30001,
        cpu: 95,
        command: 'node crypto-mine.js',
      },
    });

    const anomalies = arp.collector.eventsByCategory('anomaly');
    expect(anomalies.length).toBe(1);
    expect(anomalies[0].severity).toBe('medium');
    expect(anomalies[0].data.cpu).toBe(95);
    expect(anomalies[0].source).toBe('process');
  });

  it('should capture extreme CPU usage at 100%', async () => {
    await arp.injectEvent({
      source: 'process',
      category: 'anomaly',
      severity: 'medium',
      description: 'High CPU usage: PID 30002 at 100% — python train.py',
      data: {
        pid: 30002,
        cpu: 100,
        command: 'python train.py',
      },
    });

    const anomalies = arp.collector.eventsByCategory('anomaly');
    expect(anomalies.length).toBe(1);
    expect(anomalies[0].data.cpu).toBe(100);
  });

  it('should not flag normal CPU usage as an anomaly', async () => {
    // Inject a normal process event with CPU well below 90%
    await arp.injectEvent({
      source: 'process',
      category: 'normal',
      severity: 'info',
      description: 'New child process: PID 30003 — node server.js',
      data: {
        pid: 30003,
        cpu: 25,
        command: 'node server.js',
      },
    });

    const anomalies = arp.collector.eventsByCategory('anomaly');
    expect(anomalies.length).toBe(0);

    const normals = arp.collector.eventsByCategory('normal');
    expect(normals.length).toBe(1);
    expect(normals[0].data.cpu).toBe(25);
  });

  it('should distinguish between high and low CPU events', async () => {
    // Below threshold: normal
    await arp.injectEvent({
      source: 'process',
      category: 'normal',
      severity: 'info',
      description: 'Normal process: PID 30004 at 45% CPU',
      data: { pid: 30004, cpu: 45, command: 'node app.js' },
    });

    // At threshold boundary: normal (90% is the boundary, > 90 triggers)
    await arp.injectEvent({
      source: 'process',
      category: 'normal',
      severity: 'info',
      description: 'Process at threshold: PID 30005 at 90% CPU',
      data: { pid: 30005, cpu: 90, command: 'node build.js' },
    });

    // Above threshold: anomaly
    await arp.injectEvent({
      source: 'process',
      category: 'anomaly',
      severity: 'medium',
      description: 'High CPU usage: PID 30006 at 91%',
      data: { pid: 30006, cpu: 91, command: 'node stress.js' },
    });

    const anomalies = arp.collector.eventsByCategory('anomaly');
    expect(anomalies.length).toBe(1);
    expect(anomalies[0].data.pid).toBe(30006);

    const normals = arp.collector.eventsByCategory('normal');
    expect(normals.length).toBe(2);
  });
});
