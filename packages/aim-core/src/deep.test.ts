import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as nacl from 'tweetnacl';
import {
  createIdentity,
  loadIdentity,
  getOrCreateIdentity,
  getSecretKey,
  getPublicKey,
} from './identity';
import { sign, verify } from './crypto';
import { logEvent, readAuditLog, hasAuditLog } from './audit';
import { loadPolicy, savePolicy, checkCapability, hasPolicy } from './policy';
import { calculateTrust } from './trust';
import { AIMCore } from './';

// ─── Identity deep tests ──────────────────────────────────────────────

describe('identity (deep)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-id-deep-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('produces deterministic agentId from same keypair', () => {
    const id1 = createIdentity(tmpDir, 'test');
    // agentId starts with aim_ and is stable
    expect(id1.agentId).toMatch(/^aim_[A-Za-z0-9_-]+$/);
    // Reload produces same identity
    const id2 = loadIdentity(tmpDir);
    expect(id2!.agentId).toBe(id1.agentId);
  });

  it('generates unique identities on each call (new keypair)', () => {
    const dir1 = path.join(tmpDir, 'a');
    const dir2 = path.join(tmpDir, 'b');
    const id1 = createIdentity(dir1, 'agent-a');
    const id2 = createIdentity(dir2, 'agent-b');
    expect(id1.agentId).not.toBe(id2.agentId);
    expect(id1.publicKey).not.toBe(id2.publicKey);
    expect(id1.secretKey).not.toBe(id2.secretKey);
  });

  it('getOrCreateIdentity is idempotent', () => {
    const pub1 = getOrCreateIdentity(tmpDir, 'agent');
    const pub2 = getOrCreateIdentity(tmpDir, 'agent');
    expect(pub1.agentId).toBe(pub2.agentId);
    expect(pub1.publicKey).toBe(pub2.publicKey);
  });

  it('public identity never exposes secretKey', () => {
    const pub = getOrCreateIdentity(tmpDir, 'agent');
    expect((pub as unknown as Record<string, unknown>).secretKey).toBeUndefined();
  });

  it('stored secretKey is valid 64-byte Ed25519 key', () => {
    createIdentity(tmpDir, 'agent');
    const sk = getSecretKey(tmpDir);
    expect(sk).not.toBeNull();
    expect(sk!.length).toBe(64);
  });

  it('stored publicKey is valid 32-byte Ed25519 key', () => {
    createIdentity(tmpDir, 'agent');
    const pk = getPublicKey(tmpDir);
    expect(pk).not.toBeNull();
    expect(pk!.length).toBe(32);
  });

  it('handles corrupt identity JSON gracefully', () => {
    const dataDir = path.join(tmpDir, 'corrupt');
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'identity.json'), '{invalid json!!!', 'utf-8');
    expect(loadIdentity(dataDir)).toBeNull();
  });

  it('handles truncated identity JSON', () => {
    const dataDir = path.join(tmpDir, 'truncated');
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'identity.json'), '{"agentId":"aim_test"', 'utf-8');
    expect(loadIdentity(dataDir)).toBeNull();
  });

  it('handles empty identity file', () => {
    const dataDir = path.join(tmpDir, 'empty');
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'identity.json'), '', 'utf-8');
    expect(loadIdentity(dataDir)).toBeNull();
  });

  it('overwrites existing identity when createIdentity is called again', () => {
    const id1 = createIdentity(tmpDir, 'first');
    const id2 = createIdentity(tmpDir, 'second');
    expect(id2.agentName).toBe('second');
    expect(id2.agentId).not.toBe(id1.agentId);
    // Disk should reflect second identity
    const loaded = loadIdentity(tmpDir);
    expect(loaded!.agentName).toBe('second');
  });

  it('key pair can sign and verify', () => {
    createIdentity(tmpDir, 'signer');
    const sk = getSecretKey(tmpDir)!;
    const pk = getPublicKey(tmpDir)!;
    const msg = new Uint8Array([1, 2, 3, 4, 5]);
    const sig = sign(msg, sk);
    expect(verify(msg, sig, pk)).toBe(true);
  });

  it('handles special characters in agentName', () => {
    const id = createIdentity(tmpDir, 'agent/with spaces & "quotes"');
    expect(id.agentName).toBe('agent/with spaces & "quotes"');
    const loaded = loadIdentity(tmpDir);
    expect(loaded!.agentName).toBe('agent/with spaces & "quotes"');
  });
});

// ─── Crypto deep tests ────────────────────────────────────────────────

describe('crypto (deep)', () => {
  let keypair: nacl.SignKeyPair;

  beforeEach(() => {
    keypair = nacl.sign.keyPair();
  });

  it('signs and verifies empty message', () => {
    const empty = new Uint8Array(0);
    const sig = sign(empty, keypair.secretKey);
    expect(sig.length).toBe(64);
    expect(verify(empty, sig, keypair.publicKey)).toBe(true);
  });

  it('signs and verifies single byte', () => {
    const msg = new Uint8Array([0xff]);
    const sig = sign(msg, keypair.secretKey);
    expect(verify(msg, sig, keypair.publicKey)).toBe(true);
  });

  it('signs and verifies large message (1MB)', () => {
    const large = new Uint8Array(1024 * 1024);
    for (let i = 0; i < large.length; i++) large[i] = i & 0xff;
    const sig = sign(large, keypair.secretKey);
    expect(verify(large, sig, keypair.publicKey)).toBe(true);
  });

  it('detects single-bit tampering in message', () => {
    const msg = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const sig = sign(msg, keypair.secretKey);
    // Flip one bit
    const tampered = new Uint8Array(msg);
    tampered[2] = 0x04;
    expect(verify(tampered, sig, keypair.publicKey)).toBe(false);
  });

  it('detects single-bit tampering in signature', () => {
    const msg = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const sig = sign(msg, keypair.secretKey);
    const badSig = new Uint8Array(sig);
    badSig[0] ^= 0x01;
    expect(verify(msg, badSig, keypair.publicKey)).toBe(false);
  });

  it('rejects signature from wrong keypair', () => {
    const other = nacl.sign.keyPair();
    const msg = new Uint8Array([1, 2, 3]);
    const sig = sign(msg, other.secretKey);
    expect(verify(msg, sig, keypair.publicKey)).toBe(false);
  });

  it('produces different signatures for different messages', () => {
    const msg1 = new Uint8Array([1]);
    const msg2 = new Uint8Array([2]);
    const sig1 = sign(msg1, keypair.secretKey);
    const sig2 = sign(msg2, keypair.secretKey);
    expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(false);
  });

  it('signature is always exactly 64 bytes', () => {
    for (const size of [0, 1, 32, 64, 128, 1024]) {
      const msg = new Uint8Array(size);
      const sig = sign(msg, keypair.secretKey);
      expect(sig.length).toBe(64);
    }
  });
});

// ─── Audit deep tests ─────────────────────────────────────────────────

describe('audit (deep)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-audit-deep-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('handles 1000 sequential events', () => {
    for (let i = 0; i < 1000; i++) {
      logEvent(tmpDir, {
        plugin: 'test',
        action: `action-${i}`,
        target: 'target',
        result: 'allowed',
      });
    }
    const events = readAuditLog(tmpDir);
    expect(events.length).toBe(1000);
    expect(events[0].action).toBe('action-0');
    expect(events[999].action).toBe('action-999');
  });

  it('limit returns most recent N events', () => {
    for (let i = 0; i < 50; i++) {
      logEvent(tmpDir, {
        plugin: 'test',
        action: `event-${i}`,
        target: 'target',
        result: 'allowed',
      });
    }
    const last5 = readAuditLog(tmpDir, { limit: 5 });
    expect(last5.length).toBe(5);
    expect(last5[0].action).toBe('event-45');
    expect(last5[4].action).toBe('event-49');
  });

  it('since filter excludes older events', () => {
    const ev1 = logEvent(tmpDir, {
      plugin: 'test',
      action: 'old',
      target: 'target',
      result: 'allowed',
    });
    // Log another after a small delay
    const ev2 = logEvent(tmpDir, {
      plugin: 'test',
      action: 'new',
      target: 'target',
      result: 'denied',
    });
    const filtered = readAuditLog(tmpDir, { since: ev1.timestamp });
    // Should exclude the first event (since is exclusive: > not >=)
    expect(filtered.every((e) => e.action !== 'old' || new Date(e.timestamp).getTime() > new Date(ev1.timestamp).getTime())).toBe(true);
  });

  it('preserves metadata with special characters', () => {
    logEvent(tmpDir, {
      plugin: 'test',
      action: 'meta-test',
      target: 'target',
      result: 'allowed',
      metadata: {
        path: '/tmp/file with spaces/test.json',
        unicode: 'value',
        nested: { a: 1, b: [1, 2, 3] },
        empty: '',
        nullish: null,
      },
    });
    const events = readAuditLog(tmpDir);
    expect(events[0].metadata!.path).toBe('/tmp/file with spaces/test.json');
    expect(events[0].metadata!.nested).toEqual({ a: 1, b: [1, 2, 3] });
  });

  it('handles empty audit file', () => {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'audit.jsonl'), '', 'utf-8');
    const events = readAuditLog(tmpDir);
    expect(events).toEqual([]);
  });

  it('handles audit file with trailing newlines', () => {
    logEvent(tmpDir, { plugin: 'a', action: 'b', target: 'c', result: 'allowed' });
    // Append extra newlines
    fs.appendFileSync(path.join(tmpDir, 'audit.jsonl'), '\n\n\n', 'utf-8');
    const events = readAuditLog(tmpDir);
    expect(events.length).toBe(1);
  });

  it('hasAuditLog returns false for nonexistent dir', () => {
    expect(hasAuditLog(path.join(tmpDir, 'nope'))).toBe(false);
  });

  it('hasAuditLog returns true after first event', () => {
    expect(hasAuditLog(tmpDir)).toBe(false);
    logEvent(tmpDir, { plugin: 'x', action: 'y', target: 'z', result: 'allowed' });
    expect(hasAuditLog(tmpDir)).toBe(true);
  });
});

// ─── Policy deep tests ────────────────────────────────────────────────

describe('policy (deep)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-policy-deep-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('round-trips save then load', () => {
    const policy = {
      version: '2',
      defaultAction: 'allow' as const,
      rules: [
        { capability: 'db:write', action: 'deny' as const },
        { capability: 'net:*', action: 'allow' as const, plugins: ['fetch-plugin'] },
      ],
    };
    savePolicy(tmpDir, policy);
    const loaded = loadPolicy(tmpDir);
    expect(loaded.version).toBe('2');
    expect(loaded.defaultAction).toBe('allow');
    expect(loaded.rules.length).toBe(2);
    expect(loaded.rules[0].capability).toBe('db:write');
    expect(loaded.rules[1].plugins).toEqual(['fetch-plugin']);
  });

  it('defaults to deny when no policy file', () => {
    const policy = loadPolicy(path.join(tmpDir, 'nonexistent'));
    expect(policy.defaultAction).toBe('deny');
    expect(policy.rules).toEqual([]);
  });

  it('handles corrupt YAML gracefully', () => {
    fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), '{{{{invalid yaml', 'utf-8');
    const policy = loadPolicy(tmpDir);
    expect(policy.defaultAction).toBe('deny');
    expect(policy.rules).toEqual([]);
  });

  it('handles empty YAML file', () => {
    fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), '', 'utf-8');
    const policy = loadPolicy(tmpDir);
    // empty yaml.load returns undefined/null, should fall back to defaults
    expect(policy.defaultAction).toBe('deny');
    expect(policy.rules).toEqual([]);
  });

  it('wildcard * matches any capability', () => {
    const policy = { version: '1', defaultAction: 'deny' as const, rules: [{ capability: '*', action: 'allow' as const }] };
    expect(checkCapability(policy, 'anything')).toBe(true);
    expect(checkCapability(policy, 'db:read')).toBe(true);
    expect(checkCapability(policy, 'fs:write:/tmp')).toBe(true);
  });

  it('prefix wildcard db:* matches db:read but not database:read', () => {
    const policy = {
      version: '1',
      defaultAction: 'deny' as const,
      rules: [{ capability: 'db:*', action: 'allow' as const }],
    };
    expect(checkCapability(policy, 'db:read')).toBe(true);
    expect(checkCapability(policy, 'db:write')).toBe(true);
    expect(checkCapability(policy, 'db:')).toBe(false); // Empty resource after prefix is rejected
    expect(checkCapability(policy, 'database:read')).toBe(false);
    expect(checkCapability(policy, 'db')).toBe(false);
  });

  it('first-match-wins: deny before allow', () => {
    const policy = {
      version: '1',
      defaultAction: 'allow' as const,
      rules: [
        { capability: 'fs:write:/etc', action: 'deny' as const },
        { capability: 'fs:write:*', action: 'allow' as const },
      ],
    };
    expect(checkCapability(policy, 'fs:write:/etc')).toBe(false);
    expect(checkCapability(policy, 'fs:write:/tmp')).toBe(true);
  });

  it('plugin scoping restricts rule applicability', () => {
    const policy = {
      version: '1',
      defaultAction: 'deny' as const,
      rules: [
        { capability: 'net:*', action: 'allow' as const, plugins: ['fetch-plugin'] },
      ],
    };
    expect(checkCapability(policy, 'net:http', 'fetch-plugin')).toBe(true);
    expect(checkCapability(policy, 'net:http', 'other-plugin')).toBe(false);
    expect(checkCapability(policy, 'net:http')).toBe(false); // no plugin specified
  });

  it('handles 100 rules without errors', () => {
    const rules = Array.from({ length: 100 }, (_, i) => ({
      capability: `cap:${i}`,
      action: (i % 2 === 0 ? 'allow' : 'deny') as 'allow' | 'deny',
    }));
    const policy = { version: '1', defaultAction: 'deny' as const, rules };
    expect(checkCapability(policy, 'cap:0')).toBe(true);
    expect(checkCapability(policy, 'cap:1')).toBe(false);
    expect(checkCapability(policy, 'cap:99')).toBe(false);
    expect(checkCapability(policy, 'cap:100')).toBe(false); // default deny
  });

  it('hasPolicy returns false when no file', () => {
    expect(hasPolicy(path.join(tmpDir, 'nope'))).toBe(false);
  });

  it('hasPolicy returns true after save', () => {
    expect(hasPolicy(tmpDir)).toBe(false);
    savePolicy(tmpDir, { version: '1', defaultAction: 'deny', rules: [] });
    expect(hasPolicy(tmpDir)).toBe(true);
  });
});

// ─── Trust deep tests ─────────────────────────────────────────────────

describe('trust (deep)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-trust-deep-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('zero score when nothing is configured', () => {
    const score = calculateTrust(tmpDir, false);
    expect(score.overall).toBe(0);
    expect(Object.values(score.factors).every((v) => v === 0)).toBe(true);
  });

  it('maximum score when everything is configured', () => {
    // Create policy and audit log
    savePolicy(tmpDir, { version: '1', defaultAction: 'deny', rules: [] });
    logEvent(tmpDir, { plugin: 'test', action: 'init', target: 'agent', result: 'allowed' });

    const score = calculateTrust(tmpDir, true, {
      secretsManaged: true,
      configSigned: true,
      skillsVerified: true,
      networkControlled: true,
      heartbeatMonitored: true,
    });
    expect(score.overall).toBe(1.0);
    expect(Object.values(score.factors).every((v) => v === 1.0)).toBe(true);
  });

  it('weights sum to exactly 1.0', () => {
    // Test that the weights are consistent by checking the max score
    savePolicy(tmpDir, { version: '1', defaultAction: 'deny', rules: [] });
    logEvent(tmpDir, { plugin: 'x', action: 'y', target: 'z', result: 'allowed' });
    const score = calculateTrust(tmpDir, true, {
      secretsManaged: true,
      configSigned: true,
      skillsVerified: true,
      networkControlled: true,
      heartbeatMonitored: true,
    });
    // If weights sum to 1.0 and all factors are 1.0, overall must be 1.0
    expect(score.overall).toBe(1.0);
  });

  it('identity-only score is exactly 0.20', () => {
    const score = calculateTrust(tmpDir, true);
    expect(score.overall).toBe(0.2);
    expect(score.factors.identity).toBe(1.0);
  });

  it('partial hints produce correct partial score', () => {
    const score = calculateTrust(tmpDir, true, { secretsManaged: true });
    // identity (0.20) + secretsManaged (0.15) = 0.35
    expect(score.overall).toBe(0.35);
  });

  it('false hint values produce zero for that factor', () => {
    const score = calculateTrust(tmpDir, false, {
      secretsManaged: false,
      configSigned: false,
      skillsVerified: false,
      networkControlled: false,
      heartbeatMonitored: false,
    });
    expect(score.overall).toBe(0);
  });

  it('score is deterministic (same inputs, same output)', () => {
    savePolicy(tmpDir, { version: '1', defaultAction: 'deny', rules: [] });
    logEvent(tmpDir, { plugin: 'x', action: 'y', target: 'z', result: 'allowed' });
    const hints = { secretsManaged: true, configSigned: true } as const;
    const s1 = calculateTrust(tmpDir, true, hints);
    const s2 = calculateTrust(tmpDir, true, hints);
    expect(s1.overall).toBe(s2.overall);
    expect(s1.factors).toEqual(s2.factors);
  });

  it('calculatedAt is a valid ISO timestamp', () => {
    const score = calculateTrust(tmpDir, false);
    const parsed = new Date(score.calculatedAt);
    expect(parsed.getTime()).not.toBeNaN();
  });
});

// ─── AIMCore integration deep tests ───────────────────────────────────

describe('AIMCore (deep integration)', () => {
  let tmpDir: string;
  let core: AIMCore;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-deep-'));
    core = new AIMCore({ agentName: 'deep-test', dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('full lifecycle: identity -> sign -> verify -> audit -> trust', () => {
    // 1. Identity
    const id = core.getIdentity();
    expect(id.agentId).toMatch(/^aim_/);

    // 2. Sign and verify
    const data = new Uint8Array([104, 101, 108, 108, 111]); // "hello"
    const sig = core.sign(data);
    const pk = getPublicKey(tmpDir)!;
    expect(core.verify(data, sig, pk)).toBe(true);

    // 3. Audit log
    core.logEvent({
      plugin: 'lifecycle-test',
      action: 'full-test',
      target: 'agent',
      result: 'allowed',
    });
    const events = core.readAuditLog();
    expect(events.length).toBe(1);

    // 4. Policy
    core.savePolicy({
      version: '1',
      defaultAction: 'deny',
      rules: [{ capability: 'db:read', action: 'allow' }],
    });
    expect(core.checkCapability('db:read')).toBe(true);
    expect(core.checkCapability('db:write')).toBe(false);

    // 5. Trust score
    core.setTrustHints({ secretsManaged: true, configSigned: true });
    const trust = core.calculateTrust();
    // identity (0.20) + capabilities (0.15) + auditLog (0.10) + secrets (0.15) + config (0.10) = 0.70
    expect(trust.overall).toBe(0.7);
  });

  it('sign then tamper then verify fails', () => {
    core.getIdentity();
    const data = new Uint8Array([1, 2, 3, 4]);
    const sig = core.sign(data);
    const tampered = new Uint8Array([1, 2, 3, 5]); // last byte different
    const pk = getPublicKey(tmpDir)!;
    expect(core.verify(tampered, sig, pk)).toBe(false);
  });

  it('getIdentity returns consistent result across calls', () => {
    const id1 = core.getIdentity();
    const id2 = core.getIdentity();
    const id3 = core.getIdentity();
    expect(id1.agentId).toBe(id2.agentId);
    expect(id2.agentId).toBe(id3.agentId);
  });

  it('multiple AIMCore instances on different dirs are independent', () => {
    const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-deep-2-'));
    const core2 = new AIMCore({ agentName: 'other', dataDir: dir2 });

    const id1 = core.getIdentity();
    const id2 = core2.getIdentity();
    expect(id1.agentId).not.toBe(id2.agentId);

    // Sign with one, verify with other's key should fail
    const data = new Uint8Array([1, 2, 3]);
    const sig = core.sign(data);
    const pk2 = getPublicKey(dir2)!;
    expect(core2.verify(data, sig, pk2)).toBe(false);

    fs.rmSync(dir2, { recursive: true, force: true });
  });

  it('audit log survives AIMCore re-instantiation', () => {
    core.getIdentity();
    core.logEvent({ plugin: 'p', action: 'a', target: 't', result: 'allowed' });

    // Create new core on same dir
    const core2 = new AIMCore({ agentName: 'deep-test', dataDir: tmpDir });
    const events = core2.readAuditLog();
    expect(events.length).toBe(1);
    expect(events[0].plugin).toBe('p');
  });
});
