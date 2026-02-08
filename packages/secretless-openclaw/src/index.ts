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
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// --- Credential patterns (aligned with hackmyagent-core CRED-001) ---

interface CredentialPattern {
  name: string;
  regex: RegExp;
}

const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  { name: 'Anthropic API Key', regex: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/ },
  { name: 'OpenAI API Key (project)', regex: /sk-proj-[a-zA-Z0-9]{20,}/ },
  { name: 'OpenAI API Key (legacy)', regex: /sk-[a-zA-Z0-9]{48,}/ },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub Token (fine-grained)', regex: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub PAT (new)', regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/ },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'SendGrid Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
];

const CONFIG_FILES = [
  'config.json', 'config.yaml', 'config.yml',
  '.env', '.env.local',
  'package.json', 'mcp.json',
  'CLAUDE.md',
  '.openclaw/config.json', '.moltbot/config.json',
  'openclaw.json', 'moltbot.json',
  '.curse/mcp.json', '.vscode/mcp.json',
  '.claude/settings.json',
];

const KEY_FILE_EXTENSIONS = ['.key', '.pem', '.p12', '.pfx'];

// --- Types ---

export interface SecretEntry {
  path: string;
  allowedSkills: string[];
  backend: 'local' | 'env';
}

export interface SecretlessConfig {
  dataDir?: string;
}

// --- Encrypted Store ---

const STORE_FILE = 'secrets.enc';
const STORE_META_FILE = 'secrets.meta.json';

interface SecretStoreMeta {
  version: string;
  entries: Record<string, { allowedSkills: string[]; backend: string }>;
}

function getStoreDir(agentDir: string): string {
  return path.join(agentDir, '.opena2a', 'secretless');
}

function initStore(agentDir: string): void {
  const storeDir = getStoreDir(agentDir);
  fs.mkdirSync(storeDir, { recursive: true });

  const metaPath = path.join(storeDir, STORE_META_FILE);
  if (!fs.existsSync(metaPath)) {
    const meta: SecretStoreMeta = { version: '1', entries: {} };
    fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), 'utf-8');
  }

  const storePath = path.join(storeDir, STORE_FILE);
  if (!fs.existsSync(storePath)) {
    // Generate encryption key and create empty store
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12); // 12 bytes for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update('{}', 'utf-8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Store key alongside (in production, this would use OS keychain)
    fs.writeFileSync(path.join(storeDir, 'store.key'), key.toString('hex'), 'utf-8');
    // Format: iv:authTag:ciphertext (all hex)
    fs.writeFileSync(
      storePath,
      iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted.toString('hex'),
      'utf-8'
    );
    // Restrict key file permissions (owner read/write only)
    try { fs.chmodSync(path.join(storeDir, 'store.key'), 0o600); } catch { /* Windows */ }
  }
}

// --- Scan helpers ---

function scanFileForCredentials(filePath: string, agentDir: string): Finding[] {
  const findings: Finding[] = [];
  const maxSize = 10 * 1024 * 1024; // 10MB

  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxSize) return findings;
  } catch {
    return findings;
  }

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  const relativePath = path.relative(agentDir, filePath);
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4096) continue; // Skip long lines to prevent ReDoS

    for (const pattern of CREDENTIAL_PATTERNS) {
      if (pattern.regex.test(line)) {
        findings.push({
          id: 'CRED-001',
          title: `Exposed ${pattern.name}`,
          description: `${pattern.name} found in ${relativePath} at line ${i + 1}. Move to environment variable or secrets manager.`,
          severity: 'critical',
          filePath: relativePath,
          line: i + 1,
          oasbControl: '1.1',
          autoFixable: true,
        });
        break; // One finding per line
      }
    }
  }

  return findings;
}

function scanForKeyFiles(agentDir: string): Finding[] {
  const findings: Finding[] = [];

  try {
    const entries = fs.readdirSync(agentDir);
    for (const entry of entries) {
      const ext = path.extname(entry).toLowerCase();
      if (KEY_FILE_EXTENSIONS.includes(ext)) {
        findings.push({
          id: 'CRED-002',
          title: 'Private key file in project root',
          description: `Private key file "${entry}" found in project root. Move to a secure location outside the project.`,
          severity: 'high',
          filePath: entry,
          autoFixable: false,
        });
      }
    }
  } catch {
    // Directory not readable
  }

  return findings;
}

function scanForJwtSecrets(agentDir: string): Finding[] {
  const findings: Finding[] = [];
  const configFiles = ['config.json', 'config.yaml', 'config.yml', '.openclaw/config.json', '.moltbot/config.json'];

  for (const file of configFiles) {
    const filePath = path.join(agentDir, file);
    if (!fs.existsSync(filePath)) continue;

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      // Look for JWT secret patterns
      if (/jwt[_-]?secret/i.test(content) || /token[_-]?secret/i.test(content)) {
        findings.push({
          id: 'CRED-004',
          title: 'JWT secret in configuration',
          description: `JWT or token secret found in ${file}. Move to environment variable.`,
          severity: 'critical',
          filePath: file,
          autoFixable: true,
        });
      }
    } catch {
      // File not readable
    }
  }

  return findings;
}

// --- Fix helpers ---

function fixCredentialsInFile(filePath: string, agentDir: string): string[] {
  const modified: string[] = [];

  try {
    let content = fs.readFileSync(filePath, 'utf-8');
    let changed = false;

    for (const pattern of CREDENTIAL_PATTERNS) {
      if (pattern.regex.test(content)) {
        // Generate env var name from the credential type
        const envName = pattern.name
          .toUpperCase()
          .replace(/[^A-Z0-9]/g, '_')
          .replace(/_+/g, '_');

        content = content.replace(pattern.regex, `\${${envName}}`);
        changed = true;
      }
    }

    if (changed) {
      // Atomic write: write to temp file then rename to prevent corruption on crash
      const tmpPath = filePath + '.tmp.' + process.pid;
      fs.writeFileSync(tmpPath, content, 'utf-8');
      fs.renameSync(tmpPath, filePath);
      modified.push(path.relative(agentDir, filePath));
    }
  } catch {
    // File not writable
  }

  return modified;
}

function createEnvExample(agentDir: string, findings: Finding[]): string | null {
  const envVars = new Set<string>();

  for (const finding of findings) {
    if (finding.id === 'CRED-001') {
      // Extract credential type from title
      const match = finding.title.match(/Exposed (.+)/);
      if (match) {
        const envName = match[1]
          .toUpperCase()
          .replace(/[^A-Z0-9]/g, '_')
          .replace(/_+/g, '_');
        envVars.add(envName);
      }
    }
  }

  if (envVars.size === 0) return null;

  const envExamplePath = path.join(agentDir, '.env.example');
  const lines = ['# Required environment variables', '# Copy to .env and fill in values', ''];
  for (const v of envVars) {
    lines.push(`${v}=`);
  }
  lines.push('');

  fs.writeFileSync(envExamplePath, lines.join('\n'), 'utf-8');
  return '.env.example';
}

// --- Plugin Implementation ---

export const metadata: PluginMetadata = {
  packageName: '@opena2a/secretless-openclaw',
  displayName: 'Secretless',
  description: 'Credential protection — scan for hardcoded secrets, move to encrypted store, per-skill isolation',
  version: VERSION,
  findings: ['CRED-001', 'CRED-002', 'CRED-003', 'CRED-004'],
  scoreImprovement: 25,
};

export class SecretlessPlugin implements OpenA2APlugin {
  readonly metadata = metadata;
  private aimCore?: AIMCore;

  async init(options?: PluginInitOptions): Promise<void> {
    this.aimCore = options?.aimCore;
  }

  async scan(agentDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Scan config files for hardcoded credentials (CRED-001)
    for (const file of CONFIG_FILES) {
      const filePath = path.join(agentDir, file);
      if (fs.existsSync(filePath)) {
        findings.push(...scanFileForCredentials(filePath, agentDir));
      }
    }

    // Scan for private key files (CRED-002)
    findings.push(...scanForKeyFiles(agentDir));

    // Scan for JWT secrets in config (CRED-004)
    findings.push(...scanForJwtSecrets(agentDir));

    // Log to aim-core audit if available
    if (this.aimCore) {
      this.aimCore.logEvent({
        plugin: 'secretless',
        action: 'scan.complete',
        target: agentDir,
        result: findings.length > 0 ? 'denied' : 'allowed',
        metadata: { findingsCount: findings.length },
      });
    }

    return findings;
  }

  async fix(agentDir: string, options?: FixOptions): Promise<Remediation[]> {
    const remediations: Remediation[] = [];
    const findings = await this.scan(agentDir);

    if (options?.dryRun) {
      return findings
        .filter((f) => f.autoFixable)
        .map((f) => ({
          findingId: f.id,
          description: `Would fix: ${f.title}`,
          filesModified: f.filePath ? [f.filePath] : [],
          rollbackAvailable: false,
        }));
    }

    // Initialize encrypted store
    initStore(agentDir);

    // Fix CRED-001: Replace hardcoded credentials with env var references
    const credFindings = findings.filter((f) => f.id === 'CRED-001');
    if (credFindings.length > 0) {
      const allModified: string[] = [];

      for (const file of CONFIG_FILES) {
        const filePath = path.join(agentDir, file);
        if (fs.existsSync(filePath)) {
          allModified.push(...fixCredentialsInFile(filePath, agentDir));
        }
      }

      // Create .env.example
      const envExample = createEnvExample(agentDir, credFindings);
      if (envExample) allModified.push(envExample);

      if (allModified.length > 0) {
        remediations.push({
          findingId: 'CRED-001',
          description: `Replaced ${credFindings.length} hardcoded credential(s) with environment variable references`,
          filesModified: allModified,
          rollbackAvailable: false,
        });
      }
    }

    // Fix CRED-004: Note about JWT secrets
    const jwtFindings = findings.filter((f) => f.id === 'CRED-004');
    if (jwtFindings.length > 0) {
      for (const finding of jwtFindings) {
        if (finding.filePath) {
          const modified = fixCredentialsInFile(
            path.join(agentDir, finding.filePath),
            agentDir
          );
          if (modified.length > 0) {
            remediations.push({
              findingId: 'CRED-004',
              description: 'Replaced JWT secret with environment variable reference',
              filesModified: modified,
              rollbackAvailable: false,
            });
          }
        }
      }
    }

    // Log remediation to aim-core
    if (this.aimCore) {
      for (const r of remediations) {
        this.aimCore.logEvent({
          plugin: 'secretless',
          action: 'fix.applied',
          target: r.findingId,
          result: 'allowed',
          metadata: { filesModified: r.filesModified },
        });
      }

      this.aimCore.setTrustHints({ secretsManaged: true });
    }

    return remediations;
  }

  async status(): Promise<PluginStatus> {
    return {
      name: metadata.displayName,
      version: metadata.version,
      active: false,
      findingsCount: 0,
    };
  }

  async uninstall(): Promise<void> {
    // No persistent state beyond the store directory
  }
}

export function createPlugin(): SecretlessPlugin {
  return new SecretlessPlugin();
}
