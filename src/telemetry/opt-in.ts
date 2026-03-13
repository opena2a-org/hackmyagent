/**
 * Contribution Opt-In Prompt
 *
 * Handles the user's consent to share anonymized scan findings
 * with the OpenA2A Registry. Prompts on first scan and once at
 * scan #10, then never again.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

/** Shape of the contribute config stored in ~/.opena2a/config.json */
interface Opena2aConfig {
  contribute?: {
    enabled?: boolean;
    /** Number of scans completed since install */
    scanCount?: number;
    /** Whether the prompt was shown at scan #10 */
    promptedAtTen?: boolean;
  };
  [key: string]: unknown;
}

/**
 * Resolve the path to the OpenA2A config file.
 */
function getConfigPath(): string {
  const home = process.env.OPENA2A_HOME || join(require('os').homedir(), '.opena2a');
  return join(home, 'config.json');
}

/**
 * Read the OpenA2A config file. Returns empty object if missing or invalid.
 */
function readConfig(): Opena2aConfig {
  const configPath = getConfigPath();
  try {
    if (existsSync(configPath)) {
      return JSON.parse(readFileSync(configPath, 'utf-8'));
    }
  } catch {
    // Corrupt config file -- treat as empty
  }
  return {};
}

/**
 * Write the OpenA2A config file, preserving existing fields.
 */
function writeConfig(config: Opena2aConfig): void {
  const configPath = getConfigPath();
  const dir = require('path').dirname(configPath);
  mkdirSync(dir, { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

/**
 * Check whether the contribution setting is enabled.
 *
 * Returns:
 *   true  - user explicitly opted in, or --contribute flag used
 *   false - user explicitly opted out, or --no-contribute flag used
 *   undefined - not yet configured (should prompt)
 */
export function isContributeEnabled(): boolean | undefined {
  const config = readConfig();
  if (config.contribute?.enabled === true) return true;
  if (config.contribute?.enabled === false) return false;
  return undefined;
}

/**
 * Check whether we should show the contribution prompt.
 *
 * Prompt conditions:
 *   1. contribute.enabled is undefined (never asked) and this is the first scan
 *   2. contribute.enabled is undefined and scan count has reached 10 (second chance)
 *
 * Returns false if:
 *   - contribute.enabled is explicitly set (true or false)
 *   - Non-interactive environment (no TTY)
 *   - Already prompted at scan #10
 */
export function shouldPromptContribute(): boolean {
  // Never prompt in non-interactive environments
  if (!process.stdin.isTTY || !process.stdout.isTTY) return false;

  const config = readConfig();

  // Already configured -- never prompt
  if (config.contribute?.enabled === true || config.contribute?.enabled === false) {
    return false;
  }

  const scanCount = config.contribute?.scanCount ?? 0;

  // First scan (scanCount === 0): prompt
  if (scanCount === 0) return true;

  // Tenth scan: prompt once more (second chance)
  if (scanCount >= 9 && !config.contribute?.promptedAtTen) return true;

  return false;
}

/**
 * Increment the scan count in the config file.
 * Called after each scan completes, regardless of contribution setting.
 */
export function incrementScanCount(): void {
  const config = readConfig();
  if (!config.contribute) {
    config.contribute = {};
  }
  config.contribute.scanCount = (config.contribute.scanCount ?? 0) + 1;
  writeConfig(config);
}

/**
 * Save the user's contribution choice to the config file.
 */
export function saveContributeChoice(enabled: boolean): void {
  const config = readConfig();
  if (!config.contribute) {
    config.contribute = {};
  }
  config.contribute.enabled = enabled;

  // Track that we prompted at scan #10 so we don't ask again
  const scanCount = config.contribute.scanCount ?? 0;
  if (scanCount >= 9) {
    config.contribute.promptedAtTen = true;
  }

  writeConfig(config);
}

/**
 * Display the contribution opt-in prompt and return the user's choice.
 *
 * Uses raw stdin to read a single keypress (Y/N).
 * Returns true if the user opted in, false otherwise.
 */
export async function showContributePrompt(): Promise<boolean> {
  const lines = [
    '',
    'Help improve security for the AI agent community.',
    '',
    'Share anonymized scan findings with the OpenA2A Registry?',
    'No personal data. No source code. Only check pass/fail results.',
    'You can opt out anytime: opena2a config set contribute false',
    '',
    '[Y] Yes, contribute   [N] No thanks',
  ];

  for (const line of lines) {
    process.stdout.write(line + '\n');
  }

  const answer = await readSingleKey();
  const enabled = answer.toLowerCase() === 'y';
  saveContributeChoice(enabled);

  if (enabled) {
    process.stdout.write('\nContribution enabled. Thank you.\n');
  } else {
    process.stdout.write('\nContribution disabled. You can enable it later: opena2a config set contribute true\n');
  }

  return enabled;
}

/**
 * Read a single keypress from stdin.
 * Falls back to 'n' after a 30-second timeout.
 */
function readSingleKey(): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    // Timeout after 30 seconds -- default to 'n'
    const timer = setTimeout(() => {
      cleanup();
      resolve('n');
    }, 30_000);

    function cleanup(): void {
      clearTimeout(timer);
      stdin.removeListener('data', onData);
      if (stdin.isRaw !== wasRaw) {
        stdin.setRawMode(wasRaw ?? false);
      }
      stdin.pause();
    }

    function onData(data: Buffer): void {
      const char = data.toString().trim().toLowerCase();
      cleanup();
      resolve(char || 'n');
    }

    stdin.setRawMode(true);
    stdin.resume();
    stdin.once('data', onData);
  });
}
