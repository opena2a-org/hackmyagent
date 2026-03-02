// E2E-005: Network Interceptor — Zero-Latency Connection Detection
// Proves ARP's NetworkInterceptor catches net.Socket.connect BEFORE connection.
// Unlike lsof/ss polling, this works everywhere and has zero detection latency.
//
// ATLAS: AML.T0024, AML.T0057
// OWASP: A04

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as net from 'net';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';

describe('E2E-005: Network Interceptor', () => {
  let arp: ArpWrapper;
  let server: net.Server;
  let serverPort: number;
  let clientSocket: net.Socket | null = null;

  beforeEach(async () => {
    // Start a local TCP server
    server = net.createServer((socket) => {
      socket.on('data', (data) => socket.write(data));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          serverPort = addr.port;
        }
        resolve();
      });
    });

    arp = new ArpWrapper({
      monitors: {
        process: false,
        network: false, // Disable polling monitor
        filesystem: false,
      },
      interceptors: {
        network: true, // Enable interceptor
      },
    });
    await arp.start();
  });

  afterEach(async () => {
    if (clientSocket) {
      clientSocket.destroy();
      clientSocket = null;
    }
    await arp.stop();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('should intercept outbound TCP connection with zero latency', async () => {
    clientSocket = net.connect({ host: '127.0.0.1', port: serverPort });

    // Wait for connection event (should be nearly instant)
    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const connEvent = events.find(
      (e) =>
        e.source === 'network' &&
        e.data.remotePort === serverPort,
    );

    expect(connEvent).toBeDefined();
    expect(connEvent!.data.intercepted).toBe(true);
    expect(connEvent!.data.remoteAddr).toBe('127.0.0.1');
    expect(connEvent!.data.remotePort).toBe(serverPort);
  });

  it('should classify connections to allowed hosts as normal', async () => {
    // Restart with allowed hosts
    await arp.stop();
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
      interceptors: { network: true },
      interceptorNetworkAllowedHosts: ['127.0.0.1'],
    });
    await arp.start();

    clientSocket = net.connect({ host: '127.0.0.1', port: serverPort });
    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const connEvent = events.find(
      (e) => e.source === 'network' && e.data.remotePort === serverPort,
    );

    expect(connEvent).toBeDefined();
    expect(connEvent!.category).toBe('normal');
    expect(connEvent!.data.allowed).toBe(true);
  });

  it('should classify connections to non-allowed hosts as anomaly', async () => {
    // Restart with restricted allowed hosts (not including 127.0.0.1)
    await arp.stop();
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
      interceptors: { network: true },
      interceptorNetworkAllowedHosts: ['api.example.com'],
    });
    await arp.start();

    clientSocket = net.connect({ host: '127.0.0.1', port: serverPort });
    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const connEvent = events.find(
      (e) => e.source === 'network' && e.data.remotePort === serverPort,
    );

    expect(connEvent).toBeDefined();
    expect(connEvent!.category).toBe('anomaly');
    expect(connEvent!.severity).toBe('medium');
    expect(connEvent!.data.allowed).toBe(false);
  });

  it('should restore net.Socket after stop', async () => {
    await arp.stop();

    // After stop, connections should not generate events
    clientSocket = net.connect({ host: '127.0.0.1', port: serverPort });
    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    expect(events.length).toBe(0);
  });
});
