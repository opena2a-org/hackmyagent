import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { logEvent, readAuditLog, hasAuditLog } from './audit';

describe('audit', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-audit-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('logEvent', () => {
    it('creates audit.jsonl and appends event', () => {
      const event = logEvent(tmpDir, {
        plugin: 'credvault',
        action: 'secret.resolved',
        target: 'db-prod',
        result: 'allowed',
      });

      expect(event.timestamp).toBeTruthy();
      expect(event.plugin).toBe('credvault');
      expect(event.result).toBe('allowed');

      const filePath = path.join(tmpDir, 'audit.jsonl');
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it('appends multiple events', () => {
      logEvent(tmpDir, { plugin: 'a', action: 'act1', target: 't1', result: 'allowed' });
      logEvent(tmpDir, { plugin: 'b', action: 'act2', target: 't2', result: 'denied' });
      logEvent(tmpDir, { plugin: 'c', action: 'act3', target: 't3', result: 'error' });

      const events = readAuditLog(tmpDir);
      expect(events.length).toBe(3);
      expect(events[0].plugin).toBe('a');
      expect(events[2].plugin).toBe('c');
    });

    it('includes metadata when provided', () => {
      const event = logEvent(tmpDir, {
        plugin: 'test',
        action: 'test.action',
        target: 'target',
        result: 'allowed',
        metadata: { key: 'value', count: 42 },
      });

      expect(event.metadata).toEqual({ key: 'value', count: 42 });
    });
  });

  describe('readAuditLog', () => {
    it('returns empty array when no log exists', () => {
      expect(readAuditLog(tmpDir)).toEqual([]);
    });

    it('filters by since timestamp', async () => {
      logEvent(tmpDir, { plugin: 'a', action: 'old', target: 't', result: 'allowed' });

      // Small delay to ensure different timestamps
      await new Promise((r) => setTimeout(r, 10));
      const cutoff = new Date().toISOString();
      await new Promise((r) => setTimeout(r, 10));

      logEvent(tmpDir, { plugin: 'b', action: 'new', target: 't', result: 'allowed' });

      const events = readAuditLog(tmpDir, { since: cutoff });
      expect(events.length).toBe(1);
      expect(events[0].plugin).toBe('b');
    });

    it('limits results to most recent N', () => {
      for (let i = 0; i < 10; i++) {
        logEvent(tmpDir, { plugin: `p${i}`, action: 'act', target: 't', result: 'allowed' });
      }

      const events = readAuditLog(tmpDir, { limit: 3 });
      expect(events.length).toBe(3);
      expect(events[0].plugin).toBe('p7');
      expect(events[2].plugin).toBe('p9');
    });
  });

  describe('hasAuditLog', () => {
    it('returns false when no log exists', () => {
      expect(hasAuditLog(tmpDir)).toBe(false);
    });

    it('returns true after logging an event', () => {
      logEvent(tmpDir, { plugin: 'test', action: 'act', target: 't', result: 'allowed' });
      expect(hasAuditLog(tmpDir)).toBe(true);
    });
  });
});
