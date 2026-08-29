export const VERSION = '0.1.0';

import type {
  OpenA2APlugin,
  PluginMetadata,
  PluginStatus,
  Finding,
  Remediation,
  FixOptions,
  PluginInitOptions,
} from './core';
import type { AIMCore } from '@opena2a/aim-core';
import * as fs from 'fs';
import * as path from 'path';

// --- Credential patterns (aligned with hackmyagent-core CRED-001) ---
// Catalog is exported for introspection by the lockstep test against
// `@opena2a/credential-patterns` — no runtime consumer outside this file.

export interface CredentialPattern {
  name: string;
  regex: RegExp;
}

export const CREDENTIAL_PATTERNS: CredentialPattern[] = [
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

/**
 * Source extensions this plugin reads for CRED-005.
 *
 * Character for character the list `artifact-parser.ts` classifies as
 * `source_code`, and deliberately so: #477 was not a disagreement about which
 * credential SHAPES count — the catalog above already carries the ones `secure`
 * reports — it was a disagreement about which FILES get opened. `fix-all` read
 * fourteen fixed config paths, so a `.py` or `.ts` holding an API key was
 * "Credential Protection [+] No issues found" at exit 0 while `secure` exited 1
 * with a CRITICAL on the same tree. Reading the same population is what makes
 * the two verdicts comparable; keep this list in step with that one.
 */
const SOURCE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.pyi', '.go', '.rs', '.java', '.rb',
]);

/** Directories a source sweep never descends into. */
const SKIPPED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt',
  'vendor', '__pycache__', '.venv', 'venv', 'target', '.tox', '.mypy_cache',
  '.hackmyagent-backup', '.opena2a',
]);

/** Bounds on the sweep, so a large tree cannot turn `fix-all` into a full crawl. */
const SOURCE_SWEEP_MAX_DEPTH = 8;
const SOURCE_SWEEP_MAX_FILES = 2000;

// --- Types ---

export interface SecretEntry {
  path: string;
  allowedSkills: string[];
  backend: 'local' | 'env';
}

// A credential store was created here until #431: an AES key written
// beside a ciphertext that, in every shipped version, encrypted the literal
// `{}` — nothing ever wrote an entry or read one back. A key that protects
// nothing is liability without benefit, and it sat ungitignored in the tree
// this plugin was asked to make safer. `fix-all` removes the credential from
// the config file and stores it nowhere; the user recovers the value from
// the provider or from history, and the output says so.

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

  // Sensitive key names in .env files — flag even if the value doesn't match
  // a known format (the key NAME reveals it's a credential)
  const isEnvFile = relativePath.startsWith('.env') || relativePath.endsWith('.env');
  const ENV_KEY_PATTERNS = /^(.*(?:API_KEY|SECRET_KEY|ACCESS_KEY|AUTH_TOKEN|PASSWORD|PRIVATE_KEY|CLIENT_SECRET|DATABASE_URL|MONGO_URI|REDIS_URL|JWT_SECRET|ENCRYPTION_KEY))\s*=/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4096) continue; // Skip long lines to prevent ReDoS
    if (line.trimStart().startsWith('#')) continue; // Skip comments

    let found = false;
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
        found = true;
        break; // One finding per line
      }
    }

    // For .env files, also flag by key name even if value format is unknown
    if (!found && isEnvFile) {
      const keyMatch = line.match(ENV_KEY_PATTERNS);
      if (keyMatch) {
        const keyName = keyMatch[1].trim();
        findings.push({
          id: 'CRED-001',
          title: `Hardcoded credential: ${keyName}`,
          description: `${keyName} found in ${relativePath} at line ${i + 1}. Use a secrets manager or environment variable injection instead of hardcoding values.`,
          severity: 'high',
          filePath: relativePath,
          line: i + 1,
          oasbControl: '1.1',
          autoFixable: true,
        });
      }
    }
  }

  return findings;
}

/**
 * Collect source files under `agentDir`, breadth-bounded and depth-bounded.
 * Unreadable directories are skipped rather than raised: this sweep widens what
 * the plugin can see and must not be able to fail a run that used to work.
 */
function collectSourceFiles(agentDir: string): string[] {
  const out: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: agentDir, depth: 0 }];

  while (queue.length > 0 && out.length < SOURCE_SWEEP_MAX_FILES) {
    const { dir, depth } = queue.shift()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= SOURCE_SWEEP_MAX_FILES) break;
      const full = path.join(dir, entry.name);
      // Symlinks are not followed: a link out of the tree would report a
      // finding against a path the user did not ask this command to scan.
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIPPED_DIRS.has(entry.name)) continue;
        if (depth + 1 <= SOURCE_SWEEP_MAX_DEPTH) queue.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      if (!SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
      // Already read, by name, in the config-file pass above. Reporting it
      // twice would inflate the count without naming a second credential.
      if (CONFIG_FILES.includes(path.relative(agentDir, full))) continue;
      out.push(full);
    }
  }

  return out;
}

/**
 * CRED-005 — a hardcoded credential in an ordinary source file (#477).
 *
 * NOT auto-fixable, and that is a statement about this plugin rather than about
 * the credential: `fix()` rewrites the fourteen config paths and nothing else,
 * so marking these fixable would print a remedy that never runs and would clear
 * the finding out of `remainingFindings` — the list the exit code reads. The
 * finding names the file and the line; rotating the key is the user's move.
 */
function scanSourceFilesForCredentials(agentDir: string): Finding[] {
  const findings: Finding[] = [];
  const maxSize = 10 * 1024 * 1024;
  // A pattern QUOTED in source is not a key. Config files hold values; source
  // files legitimately hold the shapes a scanner matches with, which is why
  // this guard is on this arm and not on the config-file one above.
  const regexContextMarker = /\\d|\\w|\\s|\[a-z|\[A-Z|\[0-9|\{\d+,/;
  const placeholderMarker = /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|YOUR_?KEY|YOUR_?TOKEN|REPLACE_ME|INSERT_HERE/i;

  for (const filePath of collectSourceFiles(agentDir)) {
    try {
      if (fs.statSync(filePath).size > maxSize) continue;
    } catch {
      continue;
    }

    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const relativePath = path.relative(agentDir, filePath);
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4096) continue; // Same ReDoS bound as the config pass.
      for (const pattern of CREDENTIAL_PATTERNS) {
        const m = pattern.regex.exec(line);
        if (!m) continue;
        // `continue`, not `break`: a filtered match from one pattern must not
        // hide a real key another pattern finds on the same line.
        if (regexContextMarker.test(m[0]) || placeholderMarker.test(m[0])) continue;
        findings.push({
          id: 'CRED-005',
          title: `Exposed ${pattern.name} in source`,
          description:
            `${pattern.name} found in ${relativePath} at line ${i + 1}. ` +
            'Rotate the credential, then read it from the environment or a secrets manager. ' +
            'fix-all does not rewrite source files.',
          severity: 'critical',
          filePath: relativePath,
          line: i + 1,
          oasbControl: '1.1',
          autoFixable: false,
        });
        break; // One finding per line, as the config pass does.
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
  packageName: 'hackmyagent',
  displayName: 'Credential Protection',
  description: 'Scan for hardcoded secrets and replace with environment variable references',
  version: VERSION,
  findings: ['CRED-001', 'CRED-002', 'CRED-003', 'CRED-004', 'CRED-005'],
  scoreImprovement: 25,
};

export class CredVaultPlugin implements OpenA2APlugin {
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

    // Scan ordinary source files for the same credential shapes (CRED-005).
    // Without this arm `fix-all` and `secure` returned opposite verdicts on one
    // tree — see the note on SOURCE_EXTENSIONS (#477).
    findings.push(...scanSourceFilesForCredentials(agentDir));

    // Scan for private key files (CRED-002)
    findings.push(...scanForKeyFiles(agentDir));

    // Scan for JWT secrets in config (CRED-004)
    findings.push(...scanForJwtSecrets(agentDir));

    // Log to aim-core audit if available
    if (this.aimCore) {
      this.aimCore.logEvent({
        plugin: 'credvault',
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
          plugin: 'credvault',
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
    // No persistent state
  }
}

export function createPlugin(): CredVaultPlugin {
  return new CredVaultPlugin();
}
