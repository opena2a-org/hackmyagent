export const VERSION = '0.1.0';

import type {
  OpenA2APlugin,
  PluginMetadata,
  PluginStatus,
  Finding,
  Remediation,
  FixOptions,
  PluginInitOptions,
} from '@opena2a/plugin-core';
import type { AIMCore } from '@opena2a/aim-core';

// --- Types ---

export interface SkillPin {
  /** Skill identifier (e.g., "fetch", "browser_use") */
  skillName: string;
  /** SHA-256 hash of the skill's source at pin time */
  hash: string;
  /** ISO timestamp of pinning */
  pinnedAt: string;
  /** File path of the pinned skill */
  filePath: string;
}

export interface SkillSandboxConfig {
  /** Skills that are allowed to execute shell commands */
  allowShell: string[];
  /** Skills that are allowed network access */
  allowNetwork: string[];
  /** Skills that are allowed filesystem write access */
  allowFsWrite: string[];
  /** Maximum execution time per skill invocation (ms) */
  maxExecutionTime: number;
}

export interface SkillGuardConfig {
  /** Directory for pin store. Defaults to <agentDir>/.opena2a/skillguard */
  dataDir?: string;
  /** Auto-pin new skills on first scan */
  autoPin?: boolean;
  /** Sandbox configuration */
  sandbox?: Partial<SkillSandboxConfig>;
}

// --- Plugin Implementation ---

export const metadata: PluginMetadata = {
  packageName: '@opena2a/skillguard-openclaw',
  displayName: 'SkillGuard',
  description: 'Skill integrity — hash pinning, filesystem watcher, sandbox enforcement, tamper detection',
  version: VERSION,
  findings: ['SKILL-001', 'SKILL-002', 'SKILL-003', 'SKILL-004', 'SKILL-005'],
  scoreImprovement: 12,
};

export class SkillGuardPlugin implements OpenA2APlugin {
  readonly metadata = metadata;
  private aimCore?: AIMCore;
  private config: SkillGuardConfig = {};

  async init(options?: PluginInitOptions): Promise<void> {
    this.aimCore = options?.aimCore;
    this.config = (options?.config as SkillGuardConfig) ?? {};
  }

  async scan(agentDir: string): Promise<Finding[]> {
    // TODO: Implement — check for unpinned skills, hash mismatches (tampered skills),
    // overprivileged skills (shell/network/fs access without declaration),
    // missing sandbox config
    throw new Error('Not implemented');
  }

  async fix(agentDir: string, options?: FixOptions): Promise<Remediation[]> {
    // TODO: Implement — pin all skills with SHA-256 hashes,
    // generate sandbox config based on actual skill permissions,
    // set up filesystem watcher for tamper detection
    throw new Error('Not implemented');
  }

  async status(): Promise<PluginStatus> {
    return {
      name: metadata.displayName,
      version: metadata.version,
      active: false,
      findingsCount: 0,
    };
  }

  async monitor(): Promise<void> {
    // TODO: Implement — filesystem watcher on skill directories,
    // alert on hash mismatch, block execution of tampered skills
    throw new Error('Not implemented');
  }

  async stop(): Promise<void> {
    // TODO: Implement — stop filesystem watchers
  }

  async uninstall(agentDir: string): Promise<void> {
    // TODO: Implement — remove pins and sandbox config
    throw new Error('Not implemented');
  }
}

/** Create a new SkillGuard plugin instance */
export function createPlugin(): SkillGuardPlugin {
  return new SkillGuardPlugin();
}
