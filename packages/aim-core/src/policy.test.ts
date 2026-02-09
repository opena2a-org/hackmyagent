import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadPolicy, savePolicy, checkCapability, hasPolicy } from './policy';
import type { CapabilityPolicy } from './types';

describe('policy', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-policy-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('loadPolicy', () => {
    it('returns default deny policy when no file exists', () => {
      const p = loadPolicy(tmpDir);
      expect(p.version).toBe('1');
      expect(p.defaultAction).toBe('deny');
      expect(p.rules).toEqual([]);
    });

    it('loads a YAML policy file', () => {
      const yamlContent = `
version: "1"
defaultAction: allow
rules:
  - capability: "db:write"
    action: deny
  - capability: "net:*"
    action: allow
    plugins:
      - credvault
`;
      fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), yamlContent, 'utf-8');

      const p = loadPolicy(tmpDir);
      expect(p.defaultAction).toBe('allow');
      expect(p.rules.length).toBe(2);
      expect(p.rules[0].capability).toBe('db:write');
      expect(p.rules[0].action).toBe('deny');
      expect(p.rules[1].plugins).toEqual(['credvault']);
    });
  });

  describe('savePolicy', () => {
    it('writes a YAML policy file', () => {
      const p: CapabilityPolicy = {
        version: '1',
        defaultAction: 'deny',
        rules: [
          { capability: 'db:read', action: 'allow' },
        ],
      };

      savePolicy(tmpDir, p);
      expect(fs.existsSync(path.join(tmpDir, 'policy.yaml'))).toBe(true);

      const loaded = loadPolicy(tmpDir);
      expect(loaded.rules[0].capability).toBe('db:read');
      expect(loaded.rules[0].action).toBe('allow');
    });
  });

  describe('checkCapability', () => {
    it('uses default action when no rules match', () => {
      const allow: CapabilityPolicy = { version: '1', defaultAction: 'allow', rules: [] };
      const deny: CapabilityPolicy = { version: '1', defaultAction: 'deny', rules: [] };

      expect(checkCapability(allow, 'anything')).toBe(true);
      expect(checkCapability(deny, 'anything')).toBe(false);
    });

    it('matches exact capability', () => {
      const p: CapabilityPolicy = {
        version: '1',
        defaultAction: 'deny',
        rules: [{ capability: 'db:read', action: 'allow' }],
      };

      expect(checkCapability(p, 'db:read')).toBe(true);
      expect(checkCapability(p, 'db:write')).toBe(false);
    });

    it('matches wildcard capability', () => {
      const p: CapabilityPolicy = {
        version: '1',
        defaultAction: 'deny',
        rules: [{ capability: 'db:*', action: 'allow' }],
      };

      expect(checkCapability(p, 'db:read')).toBe(true);
      expect(checkCapability(p, 'db:write')).toBe(true);
      expect(checkCapability(p, 'net:connect')).toBe(false);
    });

    it('matches global wildcard', () => {
      const p: CapabilityPolicy = {
        version: '1',
        defaultAction: 'deny',
        rules: [{ capability: '*', action: 'allow' }],
      };

      expect(checkCapability(p, 'anything:here')).toBe(true);
    });

    it('respects first-match-wins ordering', () => {
      const p: CapabilityPolicy = {
        version: '1',
        defaultAction: 'deny',
        rules: [
          { capability: 'db:write', action: 'deny' },
          { capability: 'db:*', action: 'allow' },
        ],
      };

      expect(checkCapability(p, 'db:write')).toBe(false); // First rule matches
      expect(checkCapability(p, 'db:read')).toBe(true);   // Second rule matches
    });

    it('filters by plugin name', () => {
      const p: CapabilityPolicy = {
        version: '1',
        defaultAction: 'deny',
        rules: [
          { capability: 'db:read', action: 'allow', plugins: ['credvault'] },
        ],
      };

      expect(checkCapability(p, 'db:read', 'credvault')).toBe(true);
      expect(checkCapability(p, 'db:read', 'other-plugin')).toBe(false);
      expect(checkCapability(p, 'db:read')).toBe(false); // No plugin specified
    });

    it('matches nested wildcard patterns', () => {
      const p: CapabilityPolicy = {
        version: '1',
        defaultAction: 'deny',
        rules: [{ capability: 'fs:write:*', action: 'allow' }],
      };

      expect(checkCapability(p, 'fs:write:/tmp/foo')).toBe(true);
      expect(checkCapability(p, 'fs:write:/var/log')).toBe(true);
      expect(checkCapability(p, 'fs:read:/tmp/foo')).toBe(false);
    });
  });

  describe('hasPolicy', () => {
    it('returns false when no policy file exists', () => {
      expect(hasPolicy(tmpDir)).toBe(false);
    });

    it('returns true after saving a policy', () => {
      savePolicy(tmpDir, { version: '1', defaultAction: 'deny', rules: [] });
      expect(hasPolicy(tmpDir)).toBe(true);
    });
  });
});
