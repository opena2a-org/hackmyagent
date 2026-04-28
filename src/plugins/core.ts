export const VERSION = '0.1.0';

import type { AIMCore } from '@opena2a/aim-core';
import type { Evidence, Rationale, ConceptId } from '../types/finding-evidence';

// --- Plugin Interface ---

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  /** Unique finding ID (e.g., "CRED-001", "SIGN-002") */
  id: string;
  /** Human-readable title */
  title: string;
  /** Detailed description */
  description: string;
  /** Severity level */
  severity: Severity;
  /** File path where the finding was detected (if applicable) */
  filePath?: string;
  /** Line number (if applicable) */
  line?: number;
  /** OASB control ID (e.g., "1.1", "2.3") */
  oasbControl?: string;
  /** Whether this finding can be auto-fixed */
  autoFixable: boolean;
  /**
   * Structured evidence (positive | absence | mixed). Optional in v0.21.x;
   * mandatory in v0.22+. See `src/types/finding-evidence.ts`.
   */
  evidence?: Evidence;
  /** Plain-English rationale grounded in the evidence. Optional in v0.21.x. */
  rationale?: Rationale;
  /** Tag for an unfamiliar primitive the fix recommends (renderer dedupes per scan). */
  concept?: ConceptId;
}

export interface FixOptions {
  /** Run in dry-run mode (show what would change without applying) */
  dryRun?: boolean;
  /** Path to the agent/bot directory */
  agentDir?: string;
  /** Interactive mode — prompt before each fix */
  interactive?: boolean;
}

export interface Remediation {
  /** Finding ID that was remediated */
  findingId: string;
  /** What was done */
  description: string;
  /** Files modified */
  filesModified: string[];
  /** Whether a rollback is available */
  rollbackAvailable: boolean;
}

export interface PluginStatus {
  /** Plugin name */
  name: string;
  /** Plugin version */
  version: string;
  /** Whether the plugin is active and monitoring */
  active: boolean;
  /** Current findings count */
  findingsCount: number;
  /** Last scan timestamp */
  lastScan?: string;
}

export interface PluginMetadata {
  /** Plugin npm package name */
  packageName: string;
  /** Human-readable display name */
  displayName: string;
  /** Short description */
  description: string;
  /** Plugin version */
  version: string;
  /** Finding IDs this plugin addresses */
  findings: string[];
  /** Score improvement when all findings are fixed */
  scoreImprovement: number;
}

/**
 * The contract every OpenA2A security plugin implements.
 * Each plugin works standalone (no aim-core required).
 * When aim-core is provided, plugins gain identity-aware audit logging and capability checks.
 */
export interface OpenA2APlugin {
  /** Plugin metadata */
  readonly metadata: PluginMetadata;

  /** Initialize the plugin, optionally with aim-core integration */
  init(options?: PluginInitOptions): Promise<void>;

  /** Scan the agent directory and return findings */
  scan(agentDir: string): Promise<Finding[]>;

  /** Fix findings in the agent directory */
  fix(agentDir: string, options?: FixOptions): Promise<Remediation[]>;

  /** Get current plugin status */
  status(): Promise<PluginStatus>;

  /** Start background monitoring (if supported) */
  monitor?(): Promise<void>;

  /** Stop background monitoring and clean up */
  stop?(): Promise<void>;

  /** Uninstall the plugin and revert changes */
  uninstall?(agentDir: string): Promise<void>;
}

export interface PluginInitOptions {
  /** Optional aim-core instance for identity-aware features */
  aimCore?: AIMCore;
  /** Plugin-specific configuration */
  config?: Record<string, unknown>;
}

// --- Plugin Registry ---

export interface PluginRegistryEntry {
  /** Plugin metadata */
  metadata: PluginMetadata;
  /** Factory function to create the plugin */
  create: () => OpenA2APlugin;
}

const registry = new Map<string, PluginRegistryEntry>();

/** Register a plugin with the global registry. Throws if already registered. */
export function registerPlugin(entry: PluginRegistryEntry): void {
  const key = entry.metadata.packageName;
  if (registry.has(key)) {
    throw new Error(`Plugin "${key}" is already registered. Use clearRegistry() first to re-register.`);
  }
  registry.set(key, entry);
}

/** Get a registered plugin by package name */
export function getPlugin(packageName: string): PluginRegistryEntry | undefined {
  return registry.get(packageName);
}

/** List all registered plugins */
export function listPlugins(): PluginRegistryEntry[] {
  return Array.from(registry.values());
}

/** Clear the registry (for testing) */
export function clearRegistry(): void {
  registry.clear();
}
