import * as fs from 'fs';
import * as path from 'path';
import type { ARPConfig } from '../types';

/**
 * Load ARP config from YAML or JSON file.
 * Falls back to sensible defaults if no config found.
 */
export function loadConfig(configPath?: string): ARPConfig {
  if (configPath) {
    return parseConfigFile(configPath);
  }

  // Auto-discover config
  const candidates = [
    'arp.yaml', 'arp.yml', 'arp.json',
    '.opena2a/arp.yaml', '.opena2a/arp.yml', '.opena2a/arp.json',
  ];

  for (const candidate of candidates) {
    const fullPath = path.resolve(process.cwd(), candidate);
    if (fs.existsSync(fullPath)) {
      return parseConfigFile(fullPath);
    }
  }

  return defaultConfig();
}

function parseConfigFile(filePath: string): ARPConfig {
  const content = fs.readFileSync(filePath, 'utf-8');
  const ext = path.extname(filePath).toLowerCase();

  if (ext === '.json') {
    return { ...defaultConfig(), ...JSON.parse(content) };
  }

  // YAML parsing (dynamic import to keep it optional)
  try {
    const yaml = require('js-yaml');
    return { ...defaultConfig(), ...yaml.load(content) };
  } catch {
    throw new Error(`Failed to parse config: ${filePath}. Install js-yaml for YAML support.`);
  }
}

export function defaultConfig(): ARPConfig {
  return {
    agentName: path.basename(process.cwd()),
    agentDescription: undefined,
    declaredCapabilities: [],
    dataDir: path.join(process.cwd(), '.opena2a', 'arp'),
    monitors: {
      process: { enabled: true, intervalMs: 5000 },
      network: { enabled: true, intervalMs: 10000 },
      filesystem: { enabled: true },
      skill: { enabled: false },
      heartbeat: { enabled: false },
    },
    rules: [],
    intelligence: {
      enabled: true,
      adapter: 'agent-proxy',
      budgetUsd: 5.0,
      maxTokensPerCall: 300,
      maxCallsPerHour: 20,
      minSeverityForLlm: 'medium',
      enableBatching: true,
      batchWindowMs: 300000,
    },
  };
}
