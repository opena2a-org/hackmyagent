import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AIMCore } from './index';

describe('AIMCore', () => {
  let tmpDir: string;
  let aim: AIMCore;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-integration-'));
    aim = new AIMCore({ agentName: 'test-bot', dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates identity on first call', () => {
    const id = aim.getIdentity();
    expect(id.agentId).toMatch(/^aim_/);
    expect(id.agentName).toBe('test-bot');
    expect(id.publicKey).toBeTruthy();
  });

  it('returns same identity on subsequent calls', () => {
    const first = aim.getIdentity();
    const second = aim.getIdentity();
    expect(first.agentId).toBe(second.agentId);
  });

  it('logs and reads audit events', () => {
    aim.logEvent({
      plugin: 'credvault',
      action: 'secret.resolved',
      target: 'db-prod',
      result: 'allowed',
    });

    aim.logEvent({
      plugin: 'skillguard',
      action: 'skill.verified',
      target: 'fetch',
      result: 'allowed',
    });

    const events = aim.readAuditLog();
    expect(events.length).toBe(2);
    expect(events[0].plugin).toBe('credvault');
    expect(events[1].plugin).toBe('skillguard');
  });

  it('checks capabilities against policy', () => {
    aim.savePolicy({
      version: '1',
      defaultAction: 'deny',
      rules: [
        { capability: 'db:read', action: 'allow' },
        { capability: 'net:*', action: 'allow' },
      ],
    });

    expect(aim.checkCapability('db:read')).toBe(true);
    expect(aim.checkCapability('db:write')).toBe(false);
    expect(aim.checkCapability('net:http')).toBe(true);
  });

  it('signs and verifies data', () => {
    const id = aim.getIdentity();
    const data = new TextEncoder().encode('important message');

    const signature = aim.sign(data);
    expect(signature.length).toBe(64);

    const publicKey = Buffer.from(id.publicKey, 'base64');
    expect(aim.verify(data, signature, publicKey)).toBe(true);

    const tampered = new TextEncoder().encode('tampered message');
    expect(aim.verify(tampered, signature, publicKey)).toBe(false);
  });

  it('throws when signing without identity', () => {
    const freshAim = new AIMCore({
      agentName: 'no-id',
      dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aim-no-id-')),
    });

    expect(() => freshAim.sign(new Uint8Array([1, 2, 3]))).toThrow(
      'No identity found'
    );
  });

  it('calculates trust score', () => {
    // Fresh — nothing set up
    let score = aim.calculateTrust();
    expect(score.overall).toBe(0);

    // Create identity
    aim.getIdentity();
    score = aim.calculateTrust();
    expect(score.factors.identity).toBe(1.0);
    expect(score.overall).toBeGreaterThan(0);

    // Add policy + audit
    aim.savePolicy({ version: '1', defaultAction: 'deny', rules: [] });
    aim.logEvent({ plugin: 'test', action: 'act', target: 't', result: 'allowed' });

    // Add plugin hints
    aim.setTrustHints({
      secretsManaged: true,
      configSigned: true,
      skillsVerified: true,
      networkControlled: true,
      heartbeatMonitored: true,
    });

    score = aim.calculateTrust();
    expect(score.overall).toBe(1.0);
  });
});
