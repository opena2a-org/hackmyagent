import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import type { CapabilityPolicy, CapabilityRule } from './types';

const POLICY_FILE = 'policy.yaml';

const DEFAULT_POLICY: CapabilityPolicy = {
  version: '1',
  defaultAction: 'deny',
  rules: [],
};

/** Load capability policy from YAML file, or return default */
export function loadPolicy(dataDir: string): CapabilityPolicy {
  const filePath = path.join(dataDir, POLICY_FILE);
  if (!fs.existsSync(filePath)) {
    return DEFAULT_POLICY;
  }

  let parsed: Record<string, unknown> | undefined;
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    parsed = yaml.load(raw, { schema: yaml.FAILSAFE_SCHEMA }) as Record<string, unknown> | undefined;
  } catch {
    return DEFAULT_POLICY;
  }

  if (!parsed || typeof parsed !== 'object') {
    return DEFAULT_POLICY;
  }

  // Reject prototype pollution attempts
  const keys = Object.keys(parsed);
  if (keys.includes('__proto__') || keys.includes('constructor') || keys.includes('prototype')) {
    return DEFAULT_POLICY;
  }

  return {
    version: String(parsed.version ?? '1'),
    defaultAction: parsed.defaultAction === 'allow' ? 'allow' : 'deny',
    rules: Array.isArray(parsed.rules) ? parsed.rules.map(parseRule) : [],
  };
}

/** Save a capability policy to YAML file */
export function savePolicy(dataDir: string, policy: CapabilityPolicy): void {
  fs.mkdirSync(dataDir, { recursive: true });
  const filePath = path.join(dataDir, POLICY_FILE);
  const tmpPath = filePath + '.tmp.' + process.pid;
  fs.writeFileSync(tmpPath, yaml.dump(policy), 'utf-8');
  fs.renameSync(tmpPath, filePath);
}

/** Check if a capability is allowed by the policy */
export function checkCapability(
  policy: CapabilityPolicy,
  capability: string,
  plugin?: string
): boolean {
  for (const rule of policy.rules) {
    if (matchesCapability(rule.capability, capability)) {
      // If rule restricts to specific plugins, check plugin name
      if (rule.plugins && rule.plugins.length > 0) {
        if (!plugin || !rule.plugins.includes(plugin)) {
          continue; // Rule doesn't apply to this plugin
        }
      }
      return rule.action === 'allow';
    }
  }

  // No rule matched — use default
  return policy.defaultAction === 'allow';
}

/** Check if a policy file exists */
export function hasPolicy(dataDir: string): boolean {
  return fs.existsSync(path.join(dataDir, POLICY_FILE));
}

// --- Internal helpers ---

function parseRule(raw: unknown): CapabilityRule {
  const obj = raw as Record<string, unknown>;
  return {
    capability: String(obj.capability ?? '*'),
    action: obj.action === 'allow' ? 'allow' : 'deny',
    plugins: Array.isArray(obj.plugins) ? obj.plugins.map(String) : undefined,
  };
}

/**
 * Match a capability against a pattern.
 * Supports:
 *   "*"           → matches everything
 *   "db:*"        → matches "db:read", "db:write", etc.
 *   "fs:write:*"  → matches "fs:write:/tmp/foo", "fs:write:/var/log"
 *   "db:read"     → exact match
 */
function matchesCapability(pattern: string, capability: string): boolean {
  if (pattern === '*') return true;
  if (pattern === capability) return true;

  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // "db:" from "db:*"
    return capability.startsWith(prefix) && capability.length > prefix.length;
  }

  return false;
}
