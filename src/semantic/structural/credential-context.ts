/**
 * Context-Aware Credential Detection (Layer 2)
 *
 * Catches credentials that regex misses by understanding structure:
 * - URL passwords (postgres://admin:password123@host)
 * - Generic tokens in config (key-name heuristics)
 * - Short API keys below regex thresholds
 * - Secrets in instruction files (CLAUDE.md, .cursorrules)
 */

import type { SemanticFinding, AnalysisFile } from '../types';

/** Key names that indicate a secret value */
const SECRET_KEY_PATTERN =
  /^(.*_)?(secret|token|key|password|passwd|credential|auth|apikey|api_key|access_key|private_key|client_secret|signing_key|encryption_key|master_key|jwt_secret|session_secret|db_password|database_password)(_.*)?$/i;

/** URL with embedded credentials: protocol://user:password@host
 * Uses greedy .+ for password to handle @ chars in passwords.
 * The greedy match backtracks to the last valid @hostname boundary. */
const URL_CREDENTIAL_PATTERN =
  /(?:postgres|postgresql|mysql|mongodb|redis|amqp|rabbitmq|ftp|sftp|https?):\/\/([^:]+):(.+)@([a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d+)?(?:\/[^\s"',)]*)?)/gi;

/**
 * Classify a secret by its key name and value.
 * Returns { type, masked } where type is a human-readable label and
 * masked shows the first 5 chars of the value followed by ****.
 */
function classifySecret(key: string, value: string): { type: string; masked: string } {
  const v = value.trim().replace(/^["']|["']$/g, '');
  const preview = v.length > 5 ? v.slice(0, 5) + '****' : '****';

  // Value-based classification (most reliable)
  if (/^sk-ant-/.test(v)) return { type: 'Anthropic API key', masked: preview };
  if (/^sk-proj-/.test(v) || /^sk-[a-zA-Z0-9]{48,}/.test(v)) return { type: 'OpenAI API key', masked: preview };
  if (/^AKIA[0-9A-Z]{16}/.test(v)) return { type: 'AWS access key', masked: preview };
  if (/^(ghp_|ghs_|gho_|github_pat_)/.test(v)) return { type: 'GitHub token', masked: preview };
  if (/^AIza[0-9A-Za-z_-]{35}/.test(v)) return { type: 'Google API key', masked: preview };
  if (/^xoxb-/.test(v) || /^xoxa-/.test(v)) return { type: 'Slack token', masked: preview };

  // Key-name fallback
  const k = key.toLowerCase();
  if (/openai|gpt/.test(k)) return { type: 'OpenAI API key', masked: preview };
  if (/anthropic|claude/.test(k)) return { type: 'Anthropic API key', masked: preview };
  if (/aws|amazon/.test(k) && /key|secret/.test(k)) return { type: 'AWS credential', masked: preview };
  if (/github/.test(k)) return { type: 'GitHub token', masked: preview };
  if (/google|gcp/.test(k)) return { type: 'Google API key', masked: preview };
  if (/stripe/.test(k)) return { type: 'Stripe key', masked: preview };
  if (/twilio/.test(k)) return { type: 'Twilio credential', masked: preview };
  if (/sendgrid/.test(k)) return { type: 'SendGrid key', masked: preview };
  if (/slack/.test(k)) return { type: 'Slack token', masked: preview };
  if (/jwt|session/.test(k)) return { type: 'JWT/session secret', masked: preview };
  if (/password|passwd|pwd/.test(k)) return { type: 'password', masked: preview };
  if (/private.*key|signing.*key/.test(k)) return { type: 'private key', masked: preview };

  return { type: 'secret', masked: preview };
}

/** Values that are NOT secrets (env var refs, booleans, paths, etc.) */
function isNonSecretValue(value: string): boolean {
  const trimmed = value.trim().replace(/^["']|["']$/g, '');

  // Empty or whitespace
  if (!trimmed || trimmed.length === 0) return true;

  // Env var reference
  if (/^\$\{.*\}$/.test(trimmed) || /^\$[A-Z_]+$/.test(trimmed)) return true;

  // Boolean
  if (/^(true|false)$/i.test(trimmed)) return true;

  // Pure number
  if (/^\d+(\.\d+)?$/.test(trimmed)) return true;

  // File path (starts with / or ./ or ~/)
  if (/^[.~]?\//.test(trimmed) && !trimmed.includes('@')) return true;

  // URL without credentials
  if (/^https?:\/\/[^:@]*$/.test(trimmed)) return true;

  // Placeholder values
  if (/^(xxx|your[-_]|change[-_]me|replace[-_]|TODO|FIXME|placeholder|example)/i.test(trimmed)) return true;

  // Angle-bracket templates: <APIKEY>, <your_token>, <TENANT_NAME>
  if (/^<[^>]+>$/.test(trimmed)) return true;

  // Common non-secret config values
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|none|null|undefined|default)$/i.test(trimmed)) return true;

  return false;
}

/** Severity based on file location */
function severityForFile(filePath: string): 'critical' | 'high' {
  const lower = filePath.toLowerCase();

  // In LLM context window — exposed to AI provider, extractable via prompt injection
  if (
    lower.endsWith('claude.md') ||
    lower.endsWith('.cursorrules') ||
    lower.endsWith('.windsurfrules') ||
    lower.endsWith('.clinerules') ||
    lower.includes('copilot-instructions')
  ) {
    return 'critical';
  }

  // MCP configs — tool config, often committed
  if (
    lower.includes('mcp.json') ||
    lower.includes('mcp.yaml')
  ) {
    return 'critical';
  }

  // .env files that might be committed
  if (lower.includes('.env')) {
    return 'high';
  }

  // Config files
  return 'high';
}

/**
 * Detect URL-embedded passwords
 */
function detectUrlPasswords(file: AnalysisFile): SemanticFinding[] {
  const findings: SemanticFinding[] = [];
  const lines = file.content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    URL_CREDENTIAL_PATTERN.lastIndex = 0;
    let match;

    while ((match = URL_CREDENTIAL_PATTERN.exec(line)) !== null) {
      const password = match[2];
      // Skip env var references in URLs
      if (password.startsWith('${') || password.startsWith('$')) continue;
      // Skip very short passwords that might be ports
      if (password.length < 3) continue;

      const urlPwMasked = password.length > 5 ? password.slice(0, 5) + '****' : '****';
      findings.push({
        id: 'SEM-CRED-001',
        title: 'Password embedded in URL',
        description: `Database or service URL contains an inline password (${urlPwMasked}) in ${file.path}. Visible in plaintext in connection strings, logs, and process listings.`,
        rationale:
          'URL-embedded credentials are logged by proxies, shell history, and process listings. They bypass .env file protections and are easily leaked in stack traces.',
        category: 'credential',
        severity: severityForFile(file.path),
        file: file.path,
        line: i + 1,
        recommendation:
          'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
        layer: 2,
        autoFixable: false,
      });
    }
  }

  return findings;
}

/**
 * Detect generic tokens via key-name heuristics.
 * Skips MCP config and Claude settings files — detectMcpEnvSecrets handles those
 * with richer context (server name, env block path) to avoid duplicate findings.
 */
function detectGenericTokens(file: AnalysisFile): SemanticFinding[] {
  if (file.type === 'mcp_config' || file.type === 'claude_settings') {
    return [];
  }
  const findings: SemanticFinding[] = [];
  const lines = file.content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // JSON key:value patterns
    const jsonMatch = line.match(/"([^"]+)"\s*:\s*"([^"]+)"/);
    if (jsonMatch) {
      const [, key, value] = jsonMatch;
      if (SECRET_KEY_PATTERN.test(key) && !isNonSecretValue(value)) {
        // Ensure value looks like it could be a secret (min length, some entropy)
        if (value.length >= 8 && !/^[a-z]+$/i.test(value)) {
          const { type, masked } = classifySecret(key, value);
          findings.push({
            id: 'SEM-CRED-002',
            title: `${type} hardcoded in config`,
            description: `"${key}": ${masked}  — ${type} hardcoded in ${file.path}. Visible to anyone with repo access or who can read the file.`,
            rationale:
              'Config files with hardcoded secrets are commonly committed to version control. The key name and value prefix identify this as a real credential.',
            category: 'credential',
            severity: severityForFile(file.path),
            file: file.path,
            line: i + 1,
            recommendation: 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
            layer: 2,
            autoFixable: false,
          });
        }
      }
    }

    // YAML key: value patterns
    const yamlMatch = line.match(/^(\s*)([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s*(.+)$/);
    if (yamlMatch && !jsonMatch) {
      const [, , key, rawValue] = yamlMatch;
      const value = rawValue.trim().replace(/^["']|["']$/g, '');
      if (SECRET_KEY_PATTERN.test(key) && !isNonSecretValue(value)) {
        if (value.length >= 8 && !/^[a-z]+$/i.test(value)) {
          const { type, masked } = classifySecret(key, value);
          findings.push({
            id: 'SEM-CRED-002',
            title: `${type} hardcoded in config`,
            description: `"${key}": ${masked}  — ${type} hardcoded in ${file.path}. Visible to anyone with repo access or who can read the file.`,
            rationale:
              'Config files with hardcoded secrets are commonly committed to version control. The key name and value prefix identify this as a real credential.',
            category: 'credential',
            severity: severityForFile(file.path),
            file: file.path,
            line: i + 1,
            recommendation: 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
            layer: 2,
            autoFixable: false,
          });
        }
      }
    }

    // .env KEY=VALUE patterns
    const envMatch = line.match(/^([A-Z][A-Z0-9_]*)=(.+)$/);
    if (envMatch) {
      const [, key, rawValue] = envMatch;
      const value = rawValue.trim().replace(/^["']|["']$/g, '');
      if (SECRET_KEY_PATTERN.test(key) && !isNonSecretValue(value)) {
        if (value.length >= 8 && !/^[a-z]+$/i.test(value)) {
          findings.push({
            id: 'SEM-CRED-002',
            title: 'Hardcoded secret in config',
            description: `Environment variable "${key}" contains a hardcoded secret value in ${file.path}.`,
            rationale:
              '.env files with hardcoded secrets should be gitignored. If this file is committed, the secret is exposed in version control history.',
            category: 'credential',
            severity: severityForFile(file.path),
            file: file.path,
            line: i + 1,
            recommendation: `Ensure ${file.path} is in .gitignore and rotate this credential.`,
            layer: 2,
            autoFixable: false,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Detect credential-like strings in instruction files
 * (CLAUDE.md, .cursorrules, copilot-instructions.md)
 *
 * These files are loaded into the LLM context window,
 * so ANY credential here is critical severity.
 */
function detectCredentialsInInstructions(file: AnalysisFile): SemanticFinding[] {
  if (
    file.type !== 'agent_instructions' &&
    !file.path.toLowerCase().endsWith('claude.md') &&
    !file.path.toLowerCase().endsWith('.cursorrules')
  ) {
    return [];
  }

  const findings: SemanticFinding[] = [];
  const lines = file.content.split('\n');

  // Patterns that look like API keys/tokens (broader than core scanner's regex)
  const broadCredentialPatterns = [
    { name: 'API key prefix', pattern: /(?:sk-|pk-|rk-|ak-)[a-zA-Z0-9_-]{16,}/g },
    { name: 'Bearer token', pattern: /Bearer\s+[a-zA-Z0-9._-]{20,}/g },
    { name: 'Generic long token', pattern: /(?:token|key|secret|password)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{32,})['"]?/gi },
    { name: 'Base64 credential', pattern: /(?:password|secret|token|key)\s*[=:]\s*['"]?([A-Za-z0-9+/]{40,}={0,2})['"]?/gi },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { name, pattern } of broadCredentialPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        findings.push({
          id: 'SEM-CRED-003',
          title: 'Credential in agent instructions',
          description: `Detected ${name} pattern in ${file.path}. This file is loaded into the LLM context window.`,
          rationale:
            'Agent instruction files (CLAUDE.md, .cursorrules) are sent to the AI provider with every request. Any credential in these files is exposed to the AI provider and can be extracted via prompt injection attacks.',
          category: 'credential',
          severity: 'critical',
          file: file.path,
          line: i + 1,
          recommendation:
            'opena2a protect .  — scans for hardcoded secrets and encrypts them into a secure vault. Remove credentials from instruction files — they are sent to the AI provider on every request.',
          layer: 2,
          autoFixable: false,
        });
        break; // One finding per line
      }
    }
  }

  return findings;
}

/**
 * Detect secrets passed via MCP server env blocks
 */
function detectMcpEnvSecrets(file: AnalysisFile): SemanticFinding[] {
  if (file.type !== 'mcp_config' && file.type !== 'claude_settings') {
    return [];
  }

  const findings: SemanticFinding[] = [];

  let config: Record<string, unknown>;
  try {
    config = JSON.parse(file.content);
  } catch {
    return [];
  }

  const servers =
    (config as { mcpServers?: Record<string, { env?: Record<string, string> }> }).mcpServers || {};

  const lines = file.content.split('\n');

  for (const [serverName, serverConfig] of Object.entries(servers)) {
    if (!serverConfig.env) continue;

    for (const [key, value] of Object.entries(serverConfig.env)) {
      if (typeof value !== 'string') continue;
      if (SECRET_KEY_PATTERN.test(key) && !isNonSecretValue(value)) {
        // Find the line number
        let lineNum: number | undefined;
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes(`"${key}"`) && lines[i].includes(value.substring(0, 20))) {
            lineNum = i + 1;
            break;
          }
        }

        const { type: mcpSecType, masked: mcpMasked } = classifySecret(key, value);
        findings.push({
          id: 'SEM-CRED-004',
          title: `${mcpSecType} hardcoded in MCP server config`,
          description: `MCP server "${serverName}"  ${key}: ${mcpMasked}  — ${mcpSecType} hardcoded in env block of ${file.path}. MCP configs are commonly committed to version control.`,
          rationale:
            'MCP config files are typically committed to version control. Secrets in the env block are visible in plaintext and are extracted by any process that reads the config.',
          category: 'credential',
          severity: 'critical',
          file: file.path,
          line: lineNum,
          recommendation: 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
          layer: 2,
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

export class CredentialContextAnalyzer {
  analyze(files: AnalysisFile[]): SemanticFinding[] {
    const findings: SemanticFinding[] = [];

    for (const file of files) {
      findings.push(...detectUrlPasswords(file));
      findings.push(...detectGenericTokens(file));
      findings.push(...detectCredentialsInInstructions(file));
      findings.push(...detectMcpEnvSecrets(file));
    }

    return findings;
  }
}
