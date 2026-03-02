// E2E-003: Live Network Detection
// Proves ARP's NetworkMonitor detects real TCP connections via lsof/ss polling.
// No event injection — the monitor polls the OS network state directly.
//
// NOTE: Requires lsof (macOS) or ss (Linux) to be available.
// Test skips gracefully if neither tool is present.
//
// ATLAS: AML.T0024
// OWASP: A04

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { execSync } from 'child_process';
import * as net from 'net';
import * as os from 'os';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';

function hasNetworkTool(): boolean {
  try {
    if (os.platform() === 'darwin') {
      execSync('which lsof', { encoding: 'utf-8', timeout: 2000 });
    } else {
      execSync('which ss', { encoding: 'utf-8', timeout: 2000 });
    }
    return true;
  } catch {
    return false;
  }
}

describe('E2E-003: Live Network Detection', () => {
  let networkAvailable: boolean;

  beforeAll(() => {
    networkAvailable = hasNetworkTool();
  });

  let arp: ArpWrapper;
  let server: net.Server;
  let serverPort: number;
  let clientSocket: net.Socket | null = null;

  beforeEach(async () => {
    if (!networkAvailable) return;

    // Start a local TCP server on a random port
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
        network: true,
        filesystem: false,
      },
      networkIntervalMs: 1000,
    });
    await arp.start();

    // Let the initial snapshot complete
    await new Promise((r) => setTimeout(r, 1100));
  });

  afterEach(async () => {
    if (!networkAvailable) return;

    if (clientSocket) {
      clientSocket.destroy();
      clientSocket = null;
    }
    await arp.stop();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('should detect a new outbound TCP connection', async () => {
    if (!networkAvailable) {
      console.log('SKIP: lsof/ss not available — network E2E test requires system tools');
      return;
    }

    clientSocket = net.connect({ host: '127.0.0.1', port: serverPort });

    await new Promise<void>((resolve, reject) => {
      clientSocket!.on('connect', resolve);
      clientSocket!.on('error', reject);
    });

    // Send data to ensure connection is fully active
    clientSocket.write('test-payload');

    const event = await arp.waitForEvent(
      (e) =>
        e.source === 'network' &&
        e.data.remotePort === serverPort,
      15000,
    );

    expect(event).toBeDefined();
    expect(event.source).toBe('network');
    expect(event.data.remotePort).toBe(serverPort);
  });
});
