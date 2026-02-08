import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { calculateTrust } from './trust';
import { createIdentity } from './identity';
import { savePolicy } from './policy';
import { logEvent } from './audit';

describe('trust', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-trust-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns 0 trust for empty dataDir', () => {
    const score = calculateTrust(tmpDir, false);
    expect(score.overall).toBe(0);
    expect(score.factors.identity).toBe(0);
    expect(score.factors.capabilities).toBe(0);
    expect(score.factors.auditLog).toBe(0);
    expect(score.calculatedAt).toBeTruthy();
  });

  it('scores identity factor when identity exists', () => {
    const score = calculateTrust(tmpDir, true);
    expect(score.factors.identity).toBe(1.0);
    expect(score.overall).toBe(0.2); // identity weight = 0.20
  });

  it('scores capabilities factor when policy exists', () => {
    savePolicy(tmpDir, { version: '1', defaultAction: 'deny', rules: [] });
    const score = calculateTrust(tmpDir, false);
    expect(score.factors.capabilities).toBe(1.0);
    expect(score.overall).toBe(0.15); // capabilities weight = 0.15
  });

  it('scores auditLog factor when audit log exists', () => {
    logEvent(tmpDir, { plugin: 'test', action: 'act', target: 't', result: 'allowed' });
    const score = calculateTrust(tmpDir, false);
    expect(score.factors.auditLog).toBe(1.0);
    expect(score.overall).toBe(0.1); // auditLog weight = 0.10
  });

  it('scores plugin hints', () => {
    const score = calculateTrust(tmpDir, false, {
      secretsManaged: true,
      configSigned: true,
      skillsVerified: true,
      networkControlled: true,
      heartbeatMonitored: true,
    });

    expect(score.factors.secretsManaged).toBe(1.0);
    expect(score.factors.configSigned).toBe(1.0);
    expect(score.factors.skillsVerified).toBe(1.0);
    expect(score.factors.networkControlled).toBe(1.0);
    expect(score.factors.heartbeatMonitored).toBe(1.0);
    // Sum of plugin hint weights: 0.15 + 0.10 + 0.10 + 0.10 + 0.10 = 0.55
    expect(score.overall).toBe(0.55);
  });

  it('returns 1.0 when everything is active', () => {
    createIdentity(tmpDir, 'full-agent');
    savePolicy(tmpDir, { version: '1', defaultAction: 'deny', rules: [] });
    logEvent(tmpDir, { plugin: 'test', action: 'act', target: 't', result: 'allowed' });

    const score = calculateTrust(tmpDir, true, {
      secretsManaged: true,
      configSigned: true,
      skillsVerified: true,
      networkControlled: true,
      heartbeatMonitored: true,
    });

    expect(score.overall).toBe(1.0);
  });
});
