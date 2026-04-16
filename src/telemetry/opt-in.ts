/**
 * Contribution Consent and Scan Counting
 *
 * Manages the user's consent to share anonymized scan findings
 * with the OpenA2A Registry. Uses a delayed consent tip shown
 * after the 3rd scan (non-interactive, no blocking prompts).
 *
 * Config/counting is delegated to @opena2a/shared (the canonical
 * source for ~/.opena2a/config.json). If @opena2a/shared is not
 * available at runtime, falls back to a local implementation.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

// ---------------------------------------------------------------------------
// Shared-library delegation with graceful fallback
// ---------------------------------------------------------------------------

interface ConfigBackend {
  isContributeEnabled(): boolean;
  setContributeEnabled(enabled: boolean): void;
  incrementScanCount(): number;
  getScanCount(): number;
  shouldPromptContribute(): boolean;
  dismissContributePrompt(): void;
}

/** Resolved backend -- lazy-initialized on first call. */
let _backend: ConfigBackend | undefined;

/** Reset cached backend (for testing). */
export function _resetBackend(): void {
  _backend = undefined;
}

function resolveBackend(): ConfigBackend {
  if (_backend) return _backend;

  // When OPENA2A_HOME is set, always use local backend so the custom
  // home directory is respected (important for testing and isolation).
  if (!process.env.OPENA2A_HOME) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const shared = require('@opena2a/shared');
      if (
        typeof shared.isContributeEnabled === 'function' &&
        typeof shared.setContributeEnabled === 'function' &&
        typeof shared.incrementScanCount === 'function' &&
        typeof shared.shouldPromptContribute === 'function' &&
        typeof shared.dismissContributePrompt === 'function'
      ) {
        _backend = {
          isContributeEnabled: shared.isContributeEnabled,
          setContributeEnabled: shared.setContributeEnabled,
          incrementScanCount: shared.incrementScanCount,
          getScanCount: shared.getScanCount || (() => 0),
          shouldPromptContribute: shared.shouldPromptContribute,
          dismissContributePrompt: shared.dismissContributePrompt,
        };
        return _backend;
      }
    } catch {
      // @opena2a/shared not installed -- fall through to local backend
    }
  }

  _backend = createLocalBackend();
  return _backend;
}

// ---------------------------------------------------------------------------
// Local fallback (preserves original HMA behavior for environments
// where @opena2a/shared is not installed)
// ---------------------------------------------------------------------------

interface Opena2aConfig {
  contribute?: {
    enabled?: boolean;
  };
  telemetry?: {
    scanCount?: number;
    contributePromptDismissedAt?: string;
  };
  [key: string]: unknown;
}

function getConfigPath(): string {
  const home = process.env.OPENA2A_HOME || join(require('os').homedir(), '.opena2a');
  return join(home, 'config.json');
}

function readConfig(): Opena2aConfig {
  const configPath = getConfigPath();
  try {
    if (existsSync(configPath)) {
      return JSON.parse(readFileSync(configPath, 'utf-8'));
    }
  } catch {
    // Corrupt config -- treat as empty
  }
  return {};
}

function writeConfig(config: Opena2aConfig): void {
  const configPath = getConfigPath();
  const dir = require('path').dirname(configPath);
  mkdirSync(dir, { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

/** Cooldown for the consent tip: 30 days after dismissal. */
const TIP_COOLDOWN_MS = 30 * 24 * 60 * 60 * 1000;

function createLocalBackend(): ConfigBackend {
  return {
    isContributeEnabled(): boolean {
      const config = readConfig();
      return config.contribute?.enabled === true;
    },

    setContributeEnabled(enabled: boolean): void {
      const config = readConfig();
      if (!config.contribute) config.contribute = {};
      config.contribute.enabled = enabled;
      writeConfig(config);
    },

    incrementScanCount(): number {
      const config = readConfig();
      if (!config.telemetry) config.telemetry = {};
      config.telemetry.scanCount = (config.telemetry.scanCount ?? 0) + 1;
      writeConfig(config);
      return config.telemetry.scanCount;
    },

    getScanCount(): number {
      const config = readConfig();
      return config.telemetry?.scanCount ?? 0;
    },

    shouldPromptContribute(): boolean {
      const config = readConfig();
      // Already decided -- do not prompt
      if (config.contribute?.enabled === true || config.contribute?.enabled === false) {
        return false;
      }
      const count = config.telemetry?.scanCount ?? 0;
      if (count < 3) return false;

      // Check cooldown
      const dismissed = config.telemetry?.contributePromptDismissedAt;
      if (dismissed) {
        const dismissedMs = new Date(dismissed).getTime();
        if (Date.now() - dismissedMs < TIP_COOLDOWN_MS) return false;
      }

      return true;
    },

    dismissContributePrompt(): void {
      const config = readConfig();
      if (!config.telemetry) config.telemetry = {};
      config.telemetry.contributePromptDismissedAt = new Date().toISOString();
      writeConfig(config);
    },
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check whether the contribution setting is enabled.
 *
 * Returns:
 *   true  - user explicitly opted in
 *   false - user explicitly opted out (or default in shared backend)
 *   undefined - not yet configured
 */
export function isContributeEnabled(): boolean | undefined {
  return resolveBackend().isContributeEnabled() || undefined;
}

/**
 * Check whether we should show the contribution tip.
 *
 * Returns true after the 3rd scan if the user hasn't opted in,
 * opted out, or dismissed the tip within the last 30 days.
 */
export function shouldPromptContribute(): boolean {
  return resolveBackend().shouldPromptContribute();
}

/**
 * Increment the scan count. Called after each scan completes,
 * regardless of contribution setting.
 */
export function incrementScanCount(): number {
  return resolveBackend().incrementScanCount();
}

/**
 * Save the user's contribution choice to the config file.
 */
export function saveContributeChoice(enabled: boolean): void {
  resolveBackend().setContributeEnabled(enabled);
  if (!enabled) {
    resolveBackend().dismissContributePrompt();
  }
}

/**
 * Record a scan and return a consent tip string if the threshold is reached.
 *
 * After the 3rd scan, returns a non-interactive tip encouraging the user
 * to enable contribution. Returns null if tip should not be shown.
 * This replaces the previous interactive Y/N prompt.
 */
export function recordScanAndMaybeShowTip(): string | null {
  incrementScanCount();

  if (!shouldPromptContribute()) return null;

  // Mark as shown so we respect the 30-day cooldown
  resolveBackend().dismissContributePrompt();

  return [
    '',
    '  Tip: Your scans help build community trust data for MCP servers and AI agents.',
    '  Share anonymized results so other developers can make informed security decisions.',
    '  Enable: npx hackmyagent scan --contribute  (or: opena2a config contribute on)',
    '',
  ].join('\n');
}

/**
 * Display the contribution opt-in prompt and return the user's choice.
 *
 * @deprecated Use recordScanAndMaybeShowTip() instead. This is kept
 * for backward compatibility but now shows a non-interactive tip
 * rather than blocking for input.
 */
export async function showContributePrompt(): Promise<boolean> {
  const tip = recordScanAndMaybeShowTip();
  if (tip) {
    process.stdout.write(tip + '\n');
  }
  return false;
}

/**
 * One-time migration: if the legacy ~/.hackmyagent/config.json had
 * contribute=true but the unified ~/.opena2a/config.json does not,
 * migrate the opt-in so the user's YES is honored everywhere.
 *
 * Called once at startup (non-blocking, silently ignores errors).
 */
export function migrateLegacyContributeChoice(): void {
  try {
    const os = require('os');
    const path = require('path');
    const fs = require('fs');

    const legacyPath = path.join(os.homedir(), '.hackmyagent', 'config.json');
    if (!existsSync(legacyPath)) return;

    const legacy = JSON.parse(readFileSync(legacyPath, 'utf-8'));
    if (legacy.contribute !== true) return; // no opt-in to migrate

    const backend = resolveBackend();
    if (backend.isContributeEnabled()) return; // already enabled in unified config

    // User opted in via legacy check command — honor it in the unified config
    backend.setContributeEnabled(true);

    // Migrate pending scans queue to unified location
    if (Array.isArray(legacy.pendingScans) && legacy.pendingScans.length > 0) {
      const newQueuePath = path.join(
        process.env.OPENA2A_HOME || path.join(os.homedir(), '.opena2a'),
        'hma-pending-scans.json',
      );
      try {
        const dir = path.dirname(newQueuePath);
        if (!existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        let existing: unknown[] = [];
        try { existing = JSON.parse(readFileSync(newQueuePath, 'utf-8')); } catch { /* empty */ }
        writeFileSync(newQueuePath, JSON.stringify([...existing, ...legacy.pendingScans], null, 2));
      } catch { /* Non-fatal */ }
    }

    // Clear migrated fields from legacy config (keep scanCount for reference)
    delete legacy.contribute;
    delete legacy.pendingScans;
    writeFileSync(legacyPath, JSON.stringify(legacy, null, 2) + '\n');
  } catch {
    // Non-fatal: migration failure must not affect the scan
  }
}
