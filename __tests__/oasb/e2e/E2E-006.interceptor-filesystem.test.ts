// E2E-006: Filesystem Interceptor — Zero-Latency File Operation Detection
// Proves ARP's FilesystemInterceptor catches fs.readFile/writeFile BEFORE I/O.
// Unlike fs.watch, this catches reads, works on ALL paths, and has zero latency.
//
// ATLAS: AML.T0057, AML.T0018
// OWASP: A07

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as path from 'path';
import * as os from 'os';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';

// Use require() to get the same CJS module the interceptor patches
// eslint-disable-next-line @typescript-eslint/no-require-imports
const fs = require('fs');

describe('E2E-006: Filesystem Interceptor', () => {
  let arp: ArpWrapper;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arp-e2e-fsi-'));

    arp = new ArpWrapper({
      monitors: {
        process: false,
        network: false,
        filesystem: false,
      },
      interceptors: {
        filesystem: true,
      },
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  });

  it('should intercept writeFileSync to sensitive .env path', async () => {
    const envPath = path.join(tmpDir, '.env');
    fs.writeFileSync(envPath, 'SECRET=intercepted\n');

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const writeEvent = events.find(
      (e: { source: string; data: Record<string, unknown> }) =>
        e.source === 'filesystem' &&
        e.data.intercepted === true &&
        String(e.data.path).includes('.env'),
    );

    expect(writeEvent).toBeDefined();
    expect(writeEvent!.category).toBe('violation');
    expect(writeEvent!.severity).toBe('high');
    expect(writeEvent!.data.sensitive).toBe(true);
    expect(writeEvent!.data.operation).toBe('writeFileSync');
  });

  it('should intercept readFileSync on sensitive .ssh path', async () => {
    const sshPath = path.join(tmpDir, '.ssh');
    fs.mkdirSync(sshPath, { recursive: true });
    const keyPath = path.join(sshPath, 'id_rsa');
    fs.writeFileSync(keyPath, 'fake-key\n');

    // Now read it
    fs.readFileSync(keyPath, 'utf-8');

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const readEvent = events.find(
      (e: { source: string; data: Record<string, unknown> }) =>
        e.source === 'filesystem' &&
        e.data.operation === 'read' &&
        String(e.data.path).includes('.ssh'),
    );

    expect(readEvent).toBeDefined();
    expect(readEvent!.category).toBe('violation');
    expect(readEvent!.severity).toBe('high');
    expect(readEvent!.data.sensitive).toBe(true);
  });

  it('should intercept normal file writes without marking as violation', async () => {
    const normalPath = path.join(tmpDir, 'output.json');
    fs.writeFileSync(normalPath, '{"ok": true}\n');

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const writeEvent = events.find(
      (e: { source: string; data: Record<string, unknown> }) =>
        e.source === 'filesystem' &&
        e.data.intercepted === true &&
        String(e.data.path).includes('output.json'),
    );

    expect(writeEvent).toBeDefined();
    expect(writeEvent!.category).toBe('normal');
    expect(writeEvent!.severity).toBe('info');
  });

  it('should intercept .bashrc write as persistence attempt', async () => {
    const bashrcPath = path.join(tmpDir, '.bashrc');
    fs.writeFileSync(bashrcPath, 'alias x="malicious"\n');

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    const bashrcEvent = events.find(
      (e: { source: string; data: Record<string, unknown> }) =>
        e.source === 'filesystem' &&
        String(e.data.path).includes('.bashrc'),
    );

    expect(bashrcEvent).toBeDefined();
    expect(bashrcEvent!.category).toBe('violation');
    expect(bashrcEvent!.severity).toBe('high');
  });

  it('should restore fs module after stop', async () => {
    await arp.stop();

    const normalPath = path.join(tmpDir, 'after-stop.txt');
    fs.writeFileSync(normalPath, 'no events\n');

    await new Promise((r) => setTimeout(r, 50));

    const events = arp.collector.getEvents();
    expect(events.length).toBe(0);
  });
});
