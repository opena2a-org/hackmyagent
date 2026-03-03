/**
 * Shell environment and history scanning checks.
 * Scans ~/.bashrc, ~/.zshrc, ~/.profile, ~/.zshenv for exported secrets
 * and ~/.bash_history, ~/.zsh_history for credentials in command history.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import type { SecurityFinding, Severity } from './security-check';

// Credential patterns to detect in shell files
// Defined locally to keep module standalone (no import from scanner.ts)
const SHELL_CREDENTIAL_PATTERNS = [
  { name: 'ANTHROPIC_API_KEY', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/ },
  { name: 'OPENAI_API_KEY', pattern: /sk-proj-[a-zA-Z0-9]{20,}/ },
  { name: 'OPENAI_API_KEY', pattern: /sk-[a-zA-Z0-9]{48,}/ },
  { name: 'AWS_ACCESS_KEY', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'GITHUB_TOKEN', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GITHUB_TOKEN', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
  { name: 'SLACK_TOKEN', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/ },
  { name: 'GOOGLE_API_KEY', pattern: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'STRIPE_KEY', pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'SENDGRID_KEY', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
  { name: 'OPENROUTER_KEY', pattern: /sk-or-v1-[a-zA-Z0-9]{48,}/ },
  { name: 'GROQ_KEY', pattern: /gsk_[a-zA-Z0-9]{20,}/ },
  { name: 'REPLICATE_TOKEN', pattern: /r8_[a-zA-Z0-9]{20,}/ },
  { name: 'HUGGINGFACE_TOKEN', pattern: /hf_[a-zA-Z0-9]{20,}/ },
];

// Command-line patterns that indicate credentials passed as arguments
const COMMAND_CREDENTIAL_PATTERNS = [
  /curl\s+[^\n]*-H\s*["']Authorization:\s*Bearer\s+\S{20,}["']/i,
  /curl\s+[^\n]*-H\s*["']x-api-key:\s*\S{20,}["']/i,
  /--api[_-]?key[=\s]+\S{20,}/i,
  /--token[=\s]+\S{20,}/i,
  /--secret[=\s]+\S{20,}/i,
  /--password[=\s]+\S{10,}/i,
];

const SHELL_CONFIG_FILES = ['.bashrc', '.zshrc', '.profile', '.zshenv'];
const HISTORY_FILES = ['.bash_history', '.zsh_history'];
const MAX_HISTORY_LINES = 10_000;
const MAX_LINE_LENGTH = 10_000;

/**
 * Scan shell environment config files for exported secrets.
 * Checks ~/.bashrc, ~/.zshrc, ~/.profile, ~/.zshenv
 */
export async function checkShellEnvironment(): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const homeDir = os.homedir();

  for (const configFile of SHELL_CONFIG_FILES) {
    const filePath = path.join(homeDir, configFile);

    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      continue; // File doesn't exist, skip
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Skip empty lines and lines over max length
      if (!line || line.length > MAX_LINE_LENGTH) continue;

      // Skip comment lines
      if (/^\s*#/.test(line)) continue;

      // Skip env var references (${VAR} or $VAR without a literal value)
      if (/\$\{[A-Z_]+\}/.test(line) || /\$[A-Z_]+/.test(line)) {
        // But only skip if there's no literal credential pattern
        let hasCredential = false;
        for (const { pattern } of SHELL_CREDENTIAL_PATTERNS) {
          if (pattern.test(line)) {
            hasCredential = true;
            break;
          }
        }
        if (!hasCredential) continue;
      }

      for (const { name, pattern } of SHELL_CREDENTIAL_PATTERNS) {
        if (pattern.test(line)) {
          const checkId = getShellCheckId(name);
          findings.push({
            checkId,
            name: `Exposed ${name} in shell config`,
            description: `Found ${name} hardcoded in ~/${configFile}. Credentials in shell config files are loaded into every terminal session and may be captured by AI coding assistants.`,
            category: 'credential-exposure',
            severity: 'critical' as Severity,
            passed: false,
            message: `~/${configFile}:${i + 1} contains ${name}`,
            fixable: false,
            file: `~/${configFile}`,
            line: i + 1,
            fix: 'Move credentials to a secret manager. Run: npx secretless-ai doctor',
          });
          break; // One finding per line
        }
      }
    }
  }

  return findings;
}

/**
 * Scan shell history files for credentials.
 * Checks ~/.bash_history, ~/.zsh_history (last 10K lines)
 */
export async function checkShellHistory(): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const homeDir = os.homedir();

  for (const histFile of HISTORY_FILES) {
    const filePath = path.join(homeDir, histFile);

    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      continue; // File doesn't exist, skip
    }

    const allLines = content.split('\n');
    // Only scan last MAX_HISTORY_LINES
    const startIdx = Math.max(0, allLines.length - MAX_HISTORY_LINES);
    const lines = allLines.slice(startIdx);

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];

      // Skip empty lines and lines over max length
      if (!line || line.length > MAX_LINE_LENGTH) continue;

      // Strip zsh extended history timestamp prefix: `: 1234567890:0;actual command`
      const zshMatch = line.match(/^:\s*\d+:\d+;(.*)$/);
      if (zshMatch) {
        line = zshMatch[1];
      }

      const lineNum = startIdx + i + 1;
      let foundOnLine = false;

      // Check credential patterns in history (SHELLHIST-001/002)
      for (const { name, pattern } of SHELL_CREDENTIAL_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            checkId: getHistoryCheckId(name),
            name: 'Credential in shell history',
            description: `Found ${name} in ~/${histFile}. Credentials pasted into terminal are stored in history and accessible to any process running as your user.`,
            category: 'credential-exposure',
            severity: 'high' as Severity,
            passed: false,
            message: `~/${histFile}:${lineNum} contains ${name}`,
            fixable: false,
            file: `~/${histFile}`,
            line: lineNum,
            fix: 'Clear history entry and use a secret manager. Run: npx secretless-ai scan-history',
          });
          foundOnLine = true;
          break;
        }
      }

      // Check command-line credential patterns (SHELLHIST-003)
      // Only if we haven't already found a credential pattern on this line
      if (!foundOnLine) {
        for (const pattern of COMMAND_CREDENTIAL_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SHELLHIST-003',
              name: 'Credential in command arguments',
              description: `Found credential passed as command argument in ~/${histFile}. Command-line arguments are visible in process listings and stored in history.`,
              category: 'credential-exposure',
              severity: 'high' as Severity,
              passed: false,
              message: `~/${histFile}:${lineNum} contains credential in command`,
              fixable: false,
              file: `~/${histFile}`,
              line: lineNum,
              fix: 'Use environment variables instead of command-line arguments for credentials.',
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}

function getShellCheckId(credName: string): string {
  switch (credName) {
    case 'ANTHROPIC_API_KEY': return 'SHELL-001';
    case 'OPENAI_API_KEY': return 'SHELL-002';
    case 'AWS_ACCESS_KEY': return 'SHELL-003';
    default: return 'SHELL-004';
  }
}

function getHistoryCheckId(credName: string): string {
  switch (credName) {
    case 'ANTHROPIC_API_KEY':
    case 'OPENAI_API_KEY':
      return 'SHELLHIST-001';
    case 'AWS_ACCESS_KEY':
    case 'GITHUB_TOKEN':
      return 'SHELLHIST-002';
    default:
      return 'SHELLHIST-001';
  }
}
