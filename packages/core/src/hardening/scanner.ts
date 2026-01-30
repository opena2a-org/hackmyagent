/**
 * Hardening Scanner
 * Scans for security issues and optionally auto-fixes them
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import type { ScanResult, SecurityFinding, Severity } from './security-check';

export interface ScanOptions {
  targetDir: string;
  autoFix?: boolean;
  /** Preview fixes without applying them */
  dryRun?: boolean;
  /** Check IDs to ignore (e.g., ['CRED-001', 'GIT-002']) */
  ignore?: string[];
  /** File/folder paths to ignore (e.g., ['.env', 'secrets/', 'test/']) */
  ignorePaths?: string[];
}

// Patterns for detecting exposed credentials
// Each pattern is carefully tuned to minimize false positives
const CREDENTIAL_PATTERNS = [
  // Anthropic: sk-ant-api followed by version and 20+ char key
  { name: 'ANTHROPIC_API_KEY', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/ },
  // OpenAI project keys: sk-proj- prefix with 20+ chars
  { name: 'OPENAI_API_KEY', pattern: /sk-proj-[a-zA-Z0-9]{20,}/ },
  // OpenAI legacy keys: sk- followed by 48+ chars (avoid short matches)
  { name: 'OPENAI_API_KEY', pattern: /sk-[a-zA-Z0-9]{48,}/ },
  // AWS Access Key: AKIA prefix, exactly 20 chars total
  { name: 'AWS_ACCESS_KEY', pattern: /AKIA[0-9A-Z]{16}/ },
  // Note: AWS Secret Key pattern removed - generic base64 causes false positives
  // GitHub fine-grained PAT
  { name: 'GITHUB_TOKEN', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  // GitHub PAT (new format)
  { name: 'GITHUB_TOKEN', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
  // Slack tokens: very specific format
  { name: 'SLACK_TOKEN', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/ },
  // Google API keys: AIza prefix
  { name: 'GOOGLE_API_KEY', pattern: /AIza[0-9A-Za-z_-]{35}/ },
  // Stripe live/test keys
  { name: 'STRIPE_KEY', pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
  // SendGrid
  { name: 'SENDGRID_KEY', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
];

// Severity weights for score calculation
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

export class HardeningScanner {
  // Files that may be created or modified during auto-fix
  private static readonly BACKUP_FILES = [
    'config.json',
    'config.yaml',
    'config.yml',
    'mcp.json',
    'settings.json',
    '.env',
    '.env.local',
    '.gitignore',
    '.env.example',
    'CLAUDE.md',
    '.cursor/mcp.json',
    '.vscode/mcp.json',
    '.claude/settings.json',
    'package.json',
  ];

  async scan(options: ScanOptions): Promise<ScanResult> {
    const { targetDir, autoFix = false, dryRun = false, ignore = [] } = options;

    // Normalize ignore list to uppercase for case-insensitive matching
    const ignoredChecks = new Set(ignore.map((id) => id.toUpperCase()));

    // In dry-run mode, we detect what would be fixed but don't modify anything
    const shouldFix = autoFix && !dryRun;

    // Create backup before auto-fix (not in dry-run mode)
    let backupPath: string | undefined;
    if (shouldFix) {
      backupPath = await this.createBackup(targetDir);
    }

    // Track if any fix fails for atomic rollback
    let fixFailed = false;

    // Detect platform
    const platform = await this.detectPlatform(targetDir);

    // Run all checks
    const findings: SecurityFinding[] = [];

    // Credential exposure checks
    const credFindings = await this.checkCredentialExposure(targetDir, shouldFix);
    findings.push(...credFindings);

    // CLAUDE.md specific checks
    const claudeFindings = await this.checkClaudeMd(targetDir, shouldFix);
    findings.push(...claudeFindings);

    // MCP configuration checks
    const mcpFindings = await this.checkMcpConfig(targetDir, shouldFix);
    findings.push(...mcpFindings);

    // File permission checks
    const permFindings = await this.checkFilePermissions(targetDir, shouldFix);
    findings.push(...permFindings);

    // Git security checks
    const gitFindings = await this.checkGitSecurity(targetDir, shouldFix);
    findings.push(...gitFindings);

    // Network security checks
    const netFindings = await this.checkNetworkSecurity(targetDir, shouldFix);
    findings.push(...netFindings);

    // Additional MCP checks
    const mcpAdvFindings = await this.checkMcpAdvanced(targetDir, shouldFix);
    findings.push(...mcpAdvFindings);

    // Claude Code advanced checks
    const claudeAdvFindings = await this.checkClaudeAdvanced(targetDir, shouldFix);
    findings.push(...claudeAdvFindings);

    // Cursor configuration checks
    const cursorFindings = await this.checkCursorConfig(targetDir, shouldFix);
    findings.push(...cursorFindings);

    // VSCode configuration checks
    const vscodeFindings = await this.checkVscodeConfig(targetDir, shouldFix);
    findings.push(...vscodeFindings);

    // Additional credential checks
    const credAdvFindings = await this.checkCredentialsAdvanced(targetDir, shouldFix);
    findings.push(...credAdvFindings);

    // Additional permission checks
    const permAdvFindings = await this.checkPermissionsAdvanced(targetDir, shouldFix);
    findings.push(...permAdvFindings);

    // Environment and config checks
    const envFindings = await this.checkEnvironmentSecurity(targetDir, shouldFix);
    findings.push(...envFindings);

    // Logging and audit checks
    const logFindings = await this.checkLoggingSecurity(targetDir, shouldFix);
    findings.push(...logFindings);

    // Dependency checks
    const depFindings = await this.checkDependencySecurity(targetDir, shouldFix);
    findings.push(...depFindings);

    // Session and auth checks
    const authFindings = await this.checkAuthSecurity(targetDir, shouldFix);
    findings.push(...authFindings);

    // Process and runtime checks
    const procFindings = await this.checkProcessSecurity(targetDir, shouldFix);
    findings.push(...procFindings);

    // Additional Claude checks
    const claude3Findings = await this.checkClaudeExtended(targetDir, shouldFix);
    findings.push(...claude3Findings);

    // Additional MCP checks
    const mcp2Findings = await this.checkMcpExtended(targetDir, shouldFix);
    findings.push(...mcp2Findings);

    // Additional network checks
    const net2Findings = await this.checkNetworkExtended(targetDir, shouldFix);
    findings.push(...net2Findings);

    // Input/output security checks
    const ioFindings = await this.checkIOSecurity(targetDir, shouldFix);
    findings.push(...ioFindings);

    // API security checks
    const apiFindings = await this.checkAPISecurity(targetDir, shouldFix);
    findings.push(...apiFindings);

    // Secret management checks
    const secretFindings = await this.checkSecretManagement(targetDir, shouldFix);
    findings.push(...secretFindings);

    // Prompt injection defense checks
    const promptFindings = await this.checkPromptSecurity(targetDir, shouldFix);
    findings.push(...promptFindings);

    // Input validation checks
    const injFindings = await this.checkInputValidation(targetDir, shouldFix);
    findings.push(...injFindings);

    // Rate limiting checks
    const rateFindings = await this.checkRateLimiting(targetDir, shouldFix);
    findings.push(...rateFindings);

    // Session security checks
    const sessionFindings = await this.checkSessionSecurity(targetDir, shouldFix);
    findings.push(...sessionFindings);

    // Encryption checks
    const encryptFindings = await this.checkEncryption(targetDir, shouldFix);
    findings.push(...encryptFindings);

    // Audit trail checks
    const auditFindings = await this.checkAuditTrail(targetDir, shouldFix);
    findings.push(...auditFindings);

    // Sandboxing checks
    const sandboxFindings = await this.checkSandboxing(targetDir, shouldFix);
    findings.push(...sandboxFindings);

    // Tool boundary checks
    const toolFindings = await this.checkToolBoundaries(targetDir, shouldFix);
    findings.push(...toolFindings);

    // Filter out ignored checks
    const filteredFindings =
      ignoredChecks.size > 0
        ? findings.filter((f) => !ignoredChecks.has(f.checkId.toUpperCase()))
        : findings;

    // Calculate score (only on non-ignored findings)
    const { score, maxScore } = this.calculateScore(filteredFindings);

    // In dry-run mode, mark fixable failed findings with wouldFix
    if (dryRun && autoFix) {
      for (const finding of filteredFindings) {
        if (!finding.passed && finding.fixable) {
          finding.wouldFix = true;
        }
      }
    }

    // Determine if all fixes completed successfully (atomic)
    const hasFixedFindings = filteredFindings.some((f) => f.fixed);
    const atomicFix = shouldFix ? !fixFailed && hasFixedFindings : undefined;

    return {
      timestamp: new Date(),
      platform,
      findings: filteredFindings,
      score,
      maxScore,
      backupPath,
      dryRun: dryRun && autoFix ? true : undefined,
      atomicFix,
      ignored: ignoredChecks.size > 0 ? Array.from(ignoredChecks) : undefined,
    };
  }

  private async detectPlatform(targetDir: string): Promise<string> {
    const platforms: string[] = [];

    try {
      await fs.access(path.join(targetDir, 'CLAUDE.md'));
      platforms.push('claude-code');
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.cursor'));
      platforms.push('cursor');
    } catch {}

    try {
      await fs.access(path.join(targetDir, 'mcp.json'));
      platforms.push('mcp');
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.claude'));
      platforms.push('claude-code');
    } catch {}

    if (platforms.length === 0) {
      return 'generic';
    }

    return platforms.join('+');
  }

  private async checkCredentialExposure(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const exposedKeys: string[] = [];
    const fixedFiles: string[] = [];
    const envVarsToAdd: Set<string> = new Set();

    // Credential patterns with their env var names (stricter to avoid false positives)
    const credentialPatterns = [
      { name: 'ANTHROPIC_API_KEY', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g, envVar: 'ANTHROPIC_API_KEY' },
      { name: 'OPENAI_API_KEY', pattern: /sk-proj-[a-zA-Z0-9]{20,}/g, envVar: 'OPENAI_API_KEY' },
      { name: 'OPENAI_API_KEY', pattern: /sk-[a-zA-Z0-9]{48,}/g, envVar: 'OPENAI_API_KEY' },
      { name: 'AWS_ACCESS_KEY', pattern: /AKIA[0-9A-Z]{16}/g, envVar: 'AWS_ACCESS_KEY_ID' },
      { name: 'GITHUB_TOKEN', pattern: /ghp_[a-zA-Z0-9]{36}/g, envVar: 'GITHUB_TOKEN' },
      { name: 'GITHUB_TOKEN', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, envVar: 'GITHUB_TOKEN' },
      { name: 'GOOGLE_API_KEY', pattern: /AIza[0-9A-Za-z_-]{35}/g, envVar: 'GOOGLE_API_KEY' },
      { name: 'STRIPE_KEY', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, envVar: 'STRIPE_SECRET_KEY' },
    ];

    // Files to check for credentials
    const filesToCheck = [
      'config.json',
      'config.yaml',
      'config.yml',
      'mcp.json',
      'settings.json',
      '.env',
      '.env.local',
    ];

    for (const filename of filesToCheck) {
      const filePath = path.join(targetDir, filename);
      try {
        let content = await fs.readFile(filePath, 'utf-8');
        let fileModified = false;

        for (const { name, pattern, envVar } of credentialPatterns) {
          // Reset pattern lastIndex for global regex
          pattern.lastIndex = 0;

          if (pattern.test(content)) {
            // Check if it's already an env var reference
            pattern.lastIndex = 0;
            const match = content.match(pattern);

            if (match && !content.includes('${' + envVar + '}')) {
              exposedKeys.push(name);

              if (autoFix) {
                // Replace the credential with env var reference
                pattern.lastIndex = 0;
                content = content.replace(pattern, '${' + envVar + '}');
                fileModified = true;
                envVarsToAdd.add(envVar);
              }
            }
          }
        }

        if (fileModified) {
          await fs.writeFile(filePath, content);
          fixedFiles.push(filename);
        }
      } catch {
        // File doesn't exist, skip
      }
    }

    // Create .env.example if we fixed any credentials
    if (autoFix && envVarsToAdd.size > 0) {
      const envExamplePath = path.join(targetDir, '.env.example');
      let envExampleContent = '# Environment variables for this project\n# Copy to .env and fill in your values\n\n';

      for (const envVar of envVarsToAdd) {
        envExampleContent += `${envVar}=your_${envVar.toLowerCase()}_here\n`;
      }

      await fs.writeFile(envExamplePath, envExampleContent);
    }

    const passed = exposedKeys.length === 0;
    const fixed = fixedFiles.length > 0;

    findings.push({
      checkId: 'CRED-001',
      name: 'Exposed API Keys',
      description: 'API keys or secrets found in plaintext configuration files',
      category: 'credentials',
      severity: 'critical',
      passed: passed || fixed,
      message: fixed
        ? `Replaced credentials with env var references in: ${fixedFiles.join(', ')}`
        : passed
          ? 'No exposed API keys detected'
          : `Found exposed credentials: ${[...new Set(exposedKeys)].join(', ')}`,
      fixable: true,
      fixed,
      fixMessage: fixed ? `Created .env.example with: ${[...envVarsToAdd].join(', ')}` : undefined,
      details: passed && !fixed ? undefined : { keys: [...new Set(exposedKeys)], fixedFiles },
    });

    return findings;
  }

  private async checkClaudeMd(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const claudeMdPath = path.join(targetDir, 'CLAUDE.md');

    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      let hasSecrets = false;

      // Check for credentials in CLAUDE.md
      for (const { pattern } of CREDENTIAL_PATTERNS) {
        if (pattern.test(content)) {
          hasSecrets = true;
          break;
        }
      }

      findings.push({
        checkId: 'CLAUDE-001',
        name: 'CLAUDE.md Sensitive Content',
        description: 'CLAUDE.md file contains sensitive information like API keys',
        category: 'claude-code',
        severity: 'critical',
        passed: !hasSecrets,
        message: hasSecrets
          ? 'CLAUDE.md contains exposed credentials'
          : 'CLAUDE.md does not contain sensitive credentials',
        fixable: false,
      });
    } catch {
      // CLAUDE.md doesn't exist, that's fine
      findings.push({
        checkId: 'CLAUDE-001',
        name: 'CLAUDE.md Sensitive Content',
        description: 'CLAUDE.md file contains sensitive information like API keys',
        category: 'claude-code',
        severity: 'critical',
        passed: true,
        message: 'No CLAUDE.md file found (OK)',
        fixable: false,
      });
    }

    return findings;
  }

  private async checkMcpConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      const config = JSON.parse(content);

      // Check for dangerous filesystem access
      let hasRootAccess = false;
      let hasUnrestrictedShell = false;
      let mcp001Fixed = false;

      if (config.servers) {
        for (const [name, server] of Object.entries(config.servers as Record<string, { command?: string; args?: string[] }>)) {
          // Check for root filesystem access
          if (server.args) {
            const rootIndex = server.args.findIndex((arg: string) => arg === '/');
            const homeIndex = server.args.findIndex((arg: string) => arg === '~');

            if (rootIndex !== -1 || homeIndex !== -1) {
              hasRootAccess = true;

              if (autoFix) {
                // Replace "/" with "./data" and "~" with "./"
                if (rootIndex !== -1) {
                  server.args[rootIndex] = './data';
                }
                if (homeIndex !== -1) {
                  server.args[homeIndex] = './';
                }
                mcp001Fixed = true;
              }
            }
          }

          // Check for unrestricted shell access
          if (
            name.includes('shell') ||
            server.command?.includes('shell')
          ) {
            // Shell server without allowedCommands is dangerous
            if (!server.args?.some((arg: string) => arg.includes('allowed'))) {
              hasUnrestrictedShell = true;
            }
          }
        }
      }

      // Save fixed config
      if (mcp001Fixed) {
        await fs.writeFile(mcpConfigPath, JSON.stringify(config, null, 2));
      }

      findings.push({
        checkId: 'MCP-001',
        name: 'MCP Root Filesystem Access',
        description: 'MCP server configured with root or home directory access',
        category: 'mcp',
        severity: 'high',
        passed: !hasRootAccess || mcp001Fixed,
        message: mcp001Fixed
          ? 'Changed dangerous filesystem paths to scoped directories'
          : hasRootAccess
            ? 'MCP server has dangerous filesystem access (/ or ~)'
            : 'MCP filesystem access is scoped appropriately',
        fixable: true,
        fixed: mcp001Fixed,
        fixMessage: mcp001Fixed ? 'Replaced "/" with "./data" and "~" with "./"' : undefined,
      });

      findings.push({
        checkId: 'MCP-002',
        name: 'MCP Unrestricted Shell',
        description: 'MCP shell server without command restrictions',
        category: 'mcp',
        severity: 'critical',
        passed: !hasUnrestrictedShell,
        message: hasUnrestrictedShell
          ? 'MCP shell server has no command restrictions'
          : 'MCP shell server is properly restricted or not present',
        fixable: false,
      });
    } catch {
      // mcp.json doesn't exist or is invalid
      findings.push({
        checkId: 'MCP-001',
        name: 'MCP Root Filesystem Access',
        description: 'MCP server configured with root or home directory access',
        category: 'mcp',
        severity: 'high',
        passed: true,
        message: 'No mcp.json found (OK)',
        fixable: true,
      });

      findings.push({
        checkId: 'MCP-002',
        name: 'MCP Unrestricted Shell',
        description: 'MCP shell server without command restrictions',
        category: 'mcp',
        severity: 'critical',
        passed: true,
        message: 'No mcp.json found (OK)',
        fixable: false,
      });
    }

    return findings;
  }

  private async checkFilePermissions(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Files that should have restricted permissions
    const sensitiveFiles = [
      'secrets.json',
      '.env',
      '.env.local',
      'credentials.json',
      'auth.json',
    ];

    const permissionIssues: string[] = [];

    for (const filename of sensitiveFiles) {
      const filePath = path.join(targetDir, filename);
      try {
        const stats = await fs.stat(filePath);
        const mode = stats.mode & 0o777;

        // Check if world-readable (others have read permission)
        if (mode & 0o004) {
          permissionIssues.push(filename);

          if (autoFix) {
            await fs.chmod(filePath, 0o600);
          }
        }
      } catch {
        // File doesn't exist, skip
      }
    }

    const passed = permissionIssues.length === 0;
    findings.push({
      checkId: 'PERM-001',
      name: 'Sensitive File Permissions',
      description: 'Sensitive files have overly permissive permissions',
      category: 'permissions',
      severity: 'high',
      passed,
      message: passed
        ? 'All sensitive files have appropriate permissions'
        : `Files with overly permissive permissions: ${permissionIssues.join(', ')}`,
      fixable: true,
      fixed: autoFix && !passed,
      fixMessage: autoFix && !passed ? 'Changed permissions to 600' : undefined,
      details: passed ? undefined : { files: permissionIssues },
    });

    return findings;
  }

  private async checkGitSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // GIT-001: Check for missing .gitignore
    const gitignorePath = path.join(targetDir, '.gitignore');
    let gitignoreExists = false;
    let gitignoreContent = '';

    try {
      gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
      gitignoreExists = true;
    } catch {}

    // Default .gitignore content
    const defaultGitignore = `# Secrets and credentials
.env
.env.*
secrets.json
credentials.json
*.pem
*.key

# IDE
.idea/
.vscode/

# Dependencies
node_modules/

# Build
dist/
`;

    let git001Fixed = false;
    if (!gitignoreExists && autoFix) {
      await fs.writeFile(gitignorePath, defaultGitignore);
      gitignoreContent = defaultGitignore;
      gitignoreExists = true;
      git001Fixed = true;
    }

    findings.push({
      checkId: 'GIT-001',
      name: 'Missing .gitignore',
      description: 'No .gitignore file found to prevent accidental commits of sensitive files',
      category: 'git',
      severity: 'medium',
      passed: gitignoreExists,
      message: git001Fixed
        ? '.gitignore file created with recommended patterns'
        : gitignoreExists
          ? '.gitignore file present'
          : 'No .gitignore file found - sensitive files may be accidentally committed',
      fixable: true,
      fixed: git001Fixed,
      fixMessage: git001Fixed ? 'Created .gitignore with secure defaults' : undefined,
    });

    // GIT-002: Check for missing sensitive patterns in .gitignore
    const sensitivePatterns = ['.env', 'secrets.json', '*.pem', '*.key'];
    const missingPatterns: string[] = [];

    for (const pattern of sensitivePatterns) {
      if (!gitignoreContent.includes(pattern) && !gitignoreContent.includes(pattern.replace('*', ''))) {
        missingPatterns.push(pattern);
      }
    }

    let git002Fixed = false;
    if (missingPatterns.length > 0 && autoFix) {
      const patternsToAdd = '\n# Security patterns (auto-added)\n' + missingPatterns.join('\n') + '\n';
      gitignoreContent += patternsToAdd;
      await fs.writeFile(gitignorePath, gitignoreContent);
      git002Fixed = true;
    }

    findings.push({
      checkId: 'GIT-002',
      name: 'Incomplete .gitignore',
      description: '.gitignore missing patterns for sensitive files',
      category: 'git',
      severity: 'high',
      passed: missingPatterns.length === 0 || git002Fixed,
      message: git002Fixed
        ? `Added missing patterns to .gitignore: ${missingPatterns.join(', ')}`
        : missingPatterns.length === 0
          ? '.gitignore has all recommended sensitive file patterns'
          : `Missing patterns in .gitignore: ${missingPatterns.join(', ')}`,
      fixable: true,
      fixed: git002Fixed,
      fixMessage: git002Fixed ? `Added: ${missingPatterns.join(', ')}` : undefined,
      details: missingPatterns.length > 0 && !git002Fixed ? { missing: missingPatterns } : undefined,
    });

    // GIT-003: Check if .env exists but not in .gitignore
    let envExists = false;
    try {
      await fs.access(path.join(targetDir, '.env'));
      envExists = true;
    } catch {}

    // Re-read gitignore in case we modified it
    try {
      gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
    } catch {}

    const envIgnored = gitignoreContent.includes('.env');
    const envAtRisk = envExists && !envIgnored;

    let git003Fixed = false;
    if (envAtRisk && autoFix) {
      gitignoreContent += '\n.env\n';
      await fs.writeFile(gitignorePath, gitignoreContent);
      git003Fixed = true;
    }

    findings.push({
      checkId: 'GIT-003',
      name: '.env File at Risk',
      description: '.env file exists but may not be ignored by git',
      category: 'git',
      severity: 'critical',
      passed: !envAtRisk || git003Fixed,
      message: git003Fixed
        ? 'Added .env to .gitignore'
        : envAtRisk
          ? '.env file exists but is not in .gitignore - secrets may be committed!'
          : envExists
            ? '.env file is properly ignored'
            : 'No .env file present',
      fixable: true,
      fixed: git003Fixed,
    });

    return findings;
  }

  private async checkNetworkSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    let mcpContent = '';
    try {
      mcpContent = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(mcpContent);
    } catch {}

    // NET-001: Check for servers bound to 0.0.0.0
    let boundToAllInterfaces = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args?.some((arg: string) => arg.includes('0.0.0.0'))) {
          boundToAllInterfaces = true;
          break;
        }
      }
    }

    let net001Fixed = false;
    if (boundToAllInterfaces && autoFix && mcpContent) {
      // Replace 0.0.0.0 with 127.0.0.1 in the file
      const fixedContent = mcpContent.replace(/0\.0\.0\.0/g, '127.0.0.1');
      await fs.writeFile(mcpConfigPath, fixedContent);
      net001Fixed = true;
    }

    findings.push({
      checkId: 'NET-001',
      name: 'Server Bound to All Interfaces',
      description: 'MCP server bound to 0.0.0.0 exposes it to all network interfaces',
      category: 'network',
      severity: 'critical',
      passed: !boundToAllInterfaces || net001Fixed,
      message: net001Fixed
        ? 'Changed 0.0.0.0 to 127.0.0.1 in mcp.json'
        : boundToAllInterfaces
          ? 'MCP server bound to 0.0.0.0 - accessible from any network interface'
          : 'No servers bound to 0.0.0.0',
      fixable: true,
      fixed: net001Fixed,
      fixMessage: net001Fixed ? 'Replaced 0.0.0.0 with 127.0.0.1' : undefined,
    });

    // NET-002: Check for remote MCP servers without TLS
    let hasInsecureRemote = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { url?: string }>)) {
        if (server.url && server.url.startsWith('http://')) {
          hasInsecureRemote = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'NET-002',
      name: 'Remote MCP Without TLS',
      description: 'Remote MCP server configured without HTTPS',
      category: 'network',
      severity: 'high',
      passed: !hasInsecureRemote,
      message: hasInsecureRemote
        ? 'Remote MCP server using HTTP instead of HTTPS - traffic is unencrypted'
        : 'All remote MCP servers use HTTPS or no remote servers configured',
      fixable: false,
    });

    return findings;
  }

  private async checkMcpAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(content);
    } catch {}

    // Credential patterns with their env var names for auto-fix (stricter patterns to reduce false positives)
    const credPatterns = [
      { name: 'ANTHROPIC_API_KEY', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/, envVar: 'ANTHROPIC_API_KEY' },
      { name: 'OPENAI_API_KEY', pattern: /sk-proj-[a-zA-Z0-9]{20,}/, envVar: 'OPENAI_API_KEY' },
      { name: 'OPENAI_API_KEY', pattern: /sk-[a-zA-Z0-9]{48,}/, envVar: 'OPENAI_API_KEY' },
      { name: 'GITHUB_TOKEN', pattern: /ghp_[a-zA-Z0-9]{36}/, envVar: 'GITHUB_TOKEN' },
      { name: 'GITHUB_TOKEN', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/, envVar: 'GITHUB_TOKEN' },
      { name: 'GOOGLE_API_KEY', pattern: /AIza[0-9A-Za-z_-]{35}/, envVar: 'GOOGLE_API_KEY' },
      { name: 'STRIPE_KEY', pattern: /sk_live_[0-9a-zA-Z]{24,}/, envVar: 'STRIPE_SECRET_KEY' },
      { name: 'SLACK_TOKEN', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/, envVar: 'SLACK_TOKEN' },
      { name: 'SENDGRID_KEY', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, envVar: 'SENDGRID_API_KEY' },
    ];

    // MCP-003: Check for secrets in env vars
    let hasHardcodedSecrets = false;
    let mcp003Fixed = false;

    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { env?: Record<string, string> }>)) {
        if (server.env) {
          for (const [key, value] of Object.entries(server.env)) {
            // Check if value is a hardcoded secret (not a reference)
            if (typeof value === 'string' && !value.includes('${')) {
              for (const { pattern, envVar } of credPatterns) {
                if (pattern.test(value)) {
                  hasHardcodedSecrets = true;

                  if (autoFix) {
                    // Replace with env var reference
                    server.env[key] = '${' + envVar + '}';
                    mcp003Fixed = true;
                  }
                  break;
                }
              }
            }
          }
        }
      }

      // Save fixed config
      if (mcp003Fixed) {
        await fs.writeFile(mcpConfigPath, JSON.stringify(mcpConfig, null, 2));
      }
    }

    findings.push({
      checkId: 'MCP-003',
      name: 'MCP Hardcoded Secrets',
      description: 'MCP server configuration contains hardcoded secrets in environment variables',
      category: 'mcp',
      severity: 'critical',
      passed: !hasHardcodedSecrets || mcp003Fixed,
      message: mcp003Fixed
        ? 'Replaced hardcoded secrets with environment variable references'
        : hasHardcodedSecrets
          ? 'MCP server has hardcoded secrets in env vars - use environment variable references instead'
          : 'No hardcoded secrets in MCP env vars',
      fixable: true,
      fixed: mcp003Fixed,
      fixMessage: mcp003Fixed ? 'Replaced with ${ENV_VAR} references' : undefined,
    });

    // MCP-004: Check for default credentials
    const defaultPasswords = ['postgres', 'password', 'admin', 'root', '123456', 'default'];
    let hasDefaultCreds = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args) {
          const argsStr = server.args.join(' ').toLowerCase();
          for (const pwd of defaultPasswords) {
            if (argsStr.includes(`password`) && argsStr.includes(pwd)) {
              hasDefaultCreds = true;
              break;
            }
          }
        }
      }
    }

    findings.push({
      checkId: 'MCP-004',
      name: 'MCP Default Credentials',
      description: 'MCP server using default or weak credentials',
      category: 'mcp',
      severity: 'critical',
      passed: !hasDefaultCreds,
      message: hasDefaultCreds
        ? 'MCP server using default credentials - change to strong unique passwords'
        : 'No default credentials detected in MCP config',
      fixable: false,
    });

    // MCP-005: Check for wildcard tool access
    let hasWildcardTools = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { allowedTools?: string[] }>)) {
        if (server.allowedTools?.includes('*')) {
          hasWildcardTools = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'MCP-005',
      name: 'MCP Wildcard Tools',
      description: 'MCP server allows all tools without restrictions',
      category: 'mcp',
      severity: 'high',
      passed: !hasWildcardTools,
      message: hasWildcardTools
        ? 'MCP server allows all tools (*) - restrict to specific tools needed'
        : 'MCP tools are properly scoped',
      fixable: false,
    });

    return findings;
  }

  private async checkClaudeAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const claudeSettingsPath = path.join(targetDir, '.claude', 'settings.json');

    let claudeSettings: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(claudeSettingsPath, 'utf-8');
      claudeSettings = JSON.parse(content);
    } catch {}

    // CLAUDE-002: Check for overly permissive allowed commands
    let hasOverlyPermissive = false;
    const permissions = claudeSettings?.permissions as { allow?: string[] } | undefined;
    if (permissions?.allow) {
      for (const perm of permissions.allow) {
        if (perm.includes('(*)') || perm === 'Bash(*)' || perm === 'Read(*)' || perm === 'Write(*)') {
          hasOverlyPermissive = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'CLAUDE-002',
      name: 'Overly Permissive Claude Permissions',
      description: 'Claude Code settings allow unrestricted tool access',
      category: 'claude-code',
      severity: 'high',
      passed: !hasOverlyPermissive,
      message: hasOverlyPermissive
        ? 'Claude Code has overly permissive permissions (wildcards) - scope to specific paths/commands'
        : 'Claude Code permissions are appropriately scoped',
      fixable: false,
    });

    // CLAUDE-003: Check for dangerous Bash patterns
    let hasDangerousBash = false;
    const dangerousPatterns = ['rm -rf', 'rm -r', 'chmod 777', 'curl | sh', 'wget | sh', 'sudo'];
    if (permissions?.allow) {
      for (const perm of permissions.allow) {
        if (perm.startsWith('Bash(')) {
          for (const dangerous of dangerousPatterns) {
            if (perm.includes(dangerous)) {
              hasDangerousBash = true;
              break;
            }
          }
        }
      }
    }

    findings.push({
      checkId: 'CLAUDE-003',
      name: 'Dangerous Bash Permissions',
      description: 'Claude Code allows dangerous shell commands',
      category: 'claude-code',
      severity: 'critical',
      passed: !hasDangerousBash,
      message: hasDangerousBash
        ? 'Claude Code allows dangerous Bash commands (rm -rf, sudo, etc.) - remove or deny these'
        : 'No dangerous Bash patterns in Claude permissions',
      fixable: false,
    });

    return findings;
  }

  private async checkCursorConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Check multiple Cursor config locations
    const cursorPaths = [
      path.join(targetDir, '.cursor', 'rules'),
      path.join(targetDir, '.cursorrules'),
    ];

    let hasCredentialsInRules = false;
    for (const cursorPath of cursorPaths) {
      try {
        const content = await fs.readFile(cursorPath, 'utf-8');
        for (const { pattern } of CREDENTIAL_PATTERNS) {
          if (pattern.test(content)) {
            hasCredentialsInRules = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'CURSOR-001',
      name: 'Cursor Rules Contain Credentials',
      description: 'Cursor configuration files contain exposed credentials',
      category: 'cursor',
      severity: 'critical',
      passed: !hasCredentialsInRules,
      message: hasCredentialsInRules
        ? 'Cursor rules contain exposed credentials - remove and use environment variables'
        : 'No credentials found in Cursor rules',
      fixable: false,
    });

    return findings;
  }

  private async checkVscodeConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const vscodeMcpPath = path.join(targetDir, '.vscode', 'mcp.json');

    let vscodeConfig: Record<string, unknown> | null = null;
    let vscodeContent = '';
    try {
      vscodeContent = await fs.readFile(vscodeMcpPath, 'utf-8');
      vscodeConfig = JSON.parse(vscodeContent);
    } catch {}

    // VSCODE-001: Check for credentials in VSCode MCP config
    let hasCredentials = false;
    for (const { pattern } of CREDENTIAL_PATTERNS) {
      if (pattern.test(vscodeContent)) {
        hasCredentials = true;
        break;
      }
    }

    findings.push({
      checkId: 'VSCODE-001',
      name: 'VSCode MCP Config Credentials',
      description: 'VSCode MCP configuration contains exposed credentials',
      category: 'vscode',
      severity: 'critical',
      passed: !hasCredentials,
      message: hasCredentials
        ? 'VSCode MCP config contains exposed credentials'
        : 'No credentials in VSCode MCP config',
      fixable: false,
    });

    // VSCODE-002: Check for overly permissive paths
    let hasRootAccess = false;
    if (vscodeConfig?.servers) {
      for (const [, server] of Object.entries(vscodeConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args?.some((arg: string) => arg === '/' || arg === '~')) {
          hasRootAccess = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'VSCODE-002',
      name: 'VSCode MCP Root Access',
      description: 'VSCode MCP server has root or home directory access',
      category: 'vscode',
      severity: 'high',
      passed: !hasRootAccess,
      message: hasRootAccess
        ? 'VSCode MCP server has dangerous filesystem access'
        : 'VSCode MCP filesystem access is scoped',
      fixable: false,
    });

    return findings;
  }

  private async checkCredentialsAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // CRED-002: Check for private key files
    const keyExtensions = ['.key', '.pem'];
    const foundKeys: string[] = [];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (keyExtensions.some((ext) => file.endsWith(ext))) {
          foundKeys.push(file);
        }
      }
    } catch {}

    findings.push({
      checkId: 'CRED-002',
      name: 'Private Key Files',
      description: 'Private key or certificate files found in project directory',
      category: 'credentials',
      severity: 'critical',
      passed: foundKeys.length === 0,
      message: foundKeys.length === 0
        ? 'No private key files found in project root'
        : `Private key files found: ${foundKeys.join(', ')} - move to secure location`,
      fixable: false,
      details: foundKeys.length > 0 ? { files: foundKeys } : undefined,
    });

    // CRED-003: Check package.json for hardcoded secrets
    let hasSecretsInPackageJson = false;
    try {
      const content = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      for (const { pattern } of CREDENTIAL_PATTERNS) {
        if (pattern.test(content)) {
          hasSecretsInPackageJson = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'CRED-003',
      name: 'Secrets in package.json',
      description: 'package.json contains hardcoded secrets',
      category: 'credentials',
      severity: 'critical',
      passed: !hasSecretsInPackageJson,
      message: hasSecretsInPackageJson
        ? 'package.json contains hardcoded secrets - move to environment variables'
        : 'No secrets found in package.json',
      fixable: false,
    });

    // CRED-004: Check for JWT secrets in config
    let hasJwtSecret = false;
    const configFiles = ['config.json', 'config.yaml', 'config.yml', 'settings.json'];
    for (const file of configFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        if (content.includes('jwt') && (content.includes('secret') || content.includes('key'))) {
          // Check if it's a hardcoded value (not env reference)
          if (!content.includes('${') && !content.includes('process.env')) {
            hasJwtSecret = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'CRED-004',
      name: 'JWT Secret in Config',
      description: 'JWT secret found hardcoded in configuration file',
      category: 'credentials',
      severity: 'critical',
      passed: !hasJwtSecret,
      message: hasJwtSecret
        ? 'JWT secret hardcoded in config - use environment variable'
        : 'No hardcoded JWT secrets found',
      fixable: false,
    });

    return findings;
  }

  private async checkPermissionsAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // PERM-002: Check for executable config files
    const configFiles = ['config.json', 'mcp.json', 'settings.json', '.env'];
    const executableConfigs: string[] = [];

    for (const file of configFiles) {
      try {
        const stats = await fs.stat(path.join(targetDir, file));
        const mode = stats.mode & 0o777;
        if (mode & 0o111) {
          executableConfigs.push(file);
        }
      } catch {}
    }

    findings.push({
      checkId: 'PERM-002',
      name: 'Executable Config Files',
      description: 'Configuration files have executable permission',
      category: 'permissions',
      severity: 'medium',
      passed: executableConfigs.length === 0,
      message: executableConfigs.length === 0
        ? 'No config files have executable permissions'
        : `Config files with executable permission: ${executableConfigs.join(', ')}`,
      fixable: true,
      fixed: false,
      details: executableConfigs.length > 0 ? { files: executableConfigs } : undefined,
    });

    // PERM-003: Check for group-writable sensitive files
    const sensitiveFiles = ['.env', '.env.local', 'secrets.json', 'credentials.json'];
    const groupWritable: string[] = [];

    for (const file of sensitiveFiles) {
      try {
        const stats = await fs.stat(path.join(targetDir, file));
        const mode = stats.mode & 0o777;
        if (mode & 0o020) {
          groupWritable.push(file);
        }
      } catch {}
    }

    findings.push({
      checkId: 'PERM-003',
      name: 'Group-Writable Sensitive Files',
      description: 'Sensitive files have group write permission',
      category: 'permissions',
      severity: 'high',
      passed: groupWritable.length === 0,
      message: groupWritable.length === 0
        ? 'No sensitive files have group write permission'
        : `Group-writable sensitive files: ${groupWritable.join(', ')}`,
      fixable: true,
      fixed: false,
      details: groupWritable.length > 0 ? { files: groupWritable } : undefined,
    });

    return findings;
  }

  private async checkEnvironmentSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // ENV-001: Check for development mode indicators
    let devModeEnabled = false;
    const envIndicators = ['NODE_ENV=development', 'DEBUG=true', 'DEV_MODE=true'];
    const envFiles = ['.env', '.env.local', 'config.json'];

    for (const file of envFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        for (const indicator of envIndicators) {
          if (content.includes(indicator)) {
            devModeEnabled = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'ENV-001',
      name: 'Development Mode Enabled',
      description: 'Development mode indicators found in configuration',
      category: 'environment',
      severity: 'medium',
      passed: !devModeEnabled,
      message: devModeEnabled
        ? 'Development mode enabled - ensure this is disabled in production'
        : 'No development mode indicators found',
      fixable: false,
    });

    // ENV-002: Check for debug flags
    let hasDebugFlags = false;
    const debugPatterns = ['DEBUG=', 'VERBOSE=true', 'LOG_LEVEL=debug', 'TRACE=true'];

    for (const file of envFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        for (const pattern of debugPatterns) {
          if (content.includes(pattern)) {
            hasDebugFlags = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'ENV-002',
      name: 'Debug Flags Enabled',
      description: 'Debug or verbose logging flags are enabled',
      category: 'environment',
      severity: 'low',
      passed: !hasDebugFlags,
      message: hasDebugFlags
        ? 'Debug flags enabled - may expose sensitive information in logs'
        : 'No debug flags detected',
      fixable: false,
    });

    // ENV-003: Check for error verbosity settings
    let verboseErrors = false;
    const errorPatterns = ['SHOW_ERRORS=true', 'DISPLAY_ERRORS=true', 'STACK_TRACE=true'];

    for (const file of envFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        for (const pattern of errorPatterns) {
          if (content.includes(pattern)) {
            verboseErrors = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'ENV-003',
      name: 'Verbose Error Messages',
      description: 'Configuration enables verbose error messages',
      category: 'environment',
      severity: 'medium',
      passed: !verboseErrors,
      message: verboseErrors
        ? 'Verbose error messages enabled - may leak sensitive information'
        : 'Error verbosity settings are appropriate',
      fixable: false,
    });

    // ENV-004: Check for production environment validation
    let hasEnvValidation = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasEnvValidation = pkgJson.includes('dotenv') || pkgJson.includes('env-var') || pkgJson.includes('envalid');
    } catch {}

    findings.push({
      checkId: 'ENV-004',
      name: 'Environment Validation',
      description: 'No environment variable validation library detected',
      category: 'environment',
      severity: 'low',
      passed: hasEnvValidation,
      message: hasEnvValidation
        ? 'Environment validation library detected'
        : 'Consider using env validation (dotenv, envalid) to catch misconfigurations',
      fixable: false,
    });

    return findings;
  }

  private async checkLoggingSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // LOG-001: Check for logging configuration
    let hasLoggingConfig = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasLoggingConfig = pkgJson.includes('winston') || pkgJson.includes('pino') || pkgJson.includes('bunyan');
    } catch {}

    findings.push({
      checkId: 'LOG-001',
      name: 'Structured Logging',
      description: 'No structured logging library detected',
      category: 'logging',
      severity: 'low',
      passed: hasLoggingConfig,
      message: hasLoggingConfig
        ? 'Structured logging library detected'
        : 'Consider using structured logging (winston, pino) for better security auditing',
      fixable: false,
    });

    // LOG-002: Check for sensitive data in log patterns
    let sensitiveInLogs = false;
    const logPatterns = ['console.log(password', 'console.log(apiKey', 'console.log(secret', 'console.log(token'];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            for (const pattern of logPatterns) {
              if (content.toLowerCase().includes(pattern.toLowerCase())) {
                sensitiveInLogs = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'LOG-002',
      name: 'Sensitive Data in Logs',
      description: 'Potential sensitive data being logged',
      category: 'logging',
      severity: 'high',
      passed: !sensitiveInLogs,
      message: sensitiveInLogs
        ? 'Code may be logging sensitive data - review console.log statements'
        : 'No obvious sensitive data logging patterns found',
      fixable: false,
    });

    // LOG-003: Check for log file permissions
    const logFiles = ['app.log', 'error.log', 'debug.log', 'access.log'];
    const worldReadableLogs: string[] = [];

    for (const logFile of logFiles) {
      try {
        const stats = await fs.stat(path.join(targetDir, logFile));
        const mode = stats.mode & 0o777;
        if (mode & 0o004) {
          worldReadableLogs.push(logFile);
        }
      } catch {}
    }

    findings.push({
      checkId: 'LOG-003',
      name: 'Log File Permissions',
      description: 'Log files have overly permissive permissions',
      category: 'logging',
      severity: 'medium',
      passed: worldReadableLogs.length === 0,
      message: worldReadableLogs.length === 0
        ? 'No world-readable log files found'
        : `World-readable log files: ${worldReadableLogs.join(', ')}`,
      fixable: true,
      fixed: false,
    });

    // LOG-004: Check for audit logging capability
    let hasAuditLogging = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasAuditLogging = pkgJson.includes('audit') || pkgJson.includes('morgan') || pkgJson.includes('express-winston');
    } catch {}

    findings.push({
      checkId: 'LOG-004',
      name: 'Audit Logging',
      description: 'No audit logging capability detected',
      category: 'logging',
      severity: 'medium',
      passed: hasAuditLogging,
      message: hasAuditLogging
        ? 'Audit logging capability detected'
        : 'Consider implementing audit logging for security events',
      fixable: false,
    });

    return findings;
  }

  private async checkDependencySecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // DEP-001: Check for package-lock.json
    let hasLockFile = false;
    try {
      await fs.access(path.join(targetDir, 'package-lock.json'));
      hasLockFile = true;
    } catch {
      try {
        await fs.access(path.join(targetDir, 'yarn.lock'));
        hasLockFile = true;
      } catch {
        try {
          await fs.access(path.join(targetDir, 'pnpm-lock.yaml'));
          hasLockFile = true;
        } catch {}
      }
    }

    findings.push({
      checkId: 'DEP-001',
      name: 'Dependency Lock File',
      description: 'No dependency lock file found',
      category: 'dependencies',
      severity: 'medium',
      passed: hasLockFile,
      message: hasLockFile
        ? 'Dependency lock file present'
        : 'No lock file found - dependency versions may vary between installs',
      fixable: false,
    });

    // DEP-002: Check for known vulnerable packages
    const vulnerablePackages = ['event-stream', 'flatmap-stream', 'eslint-scope@3.7.2'];
    let hasVulnerablePackage = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      for (const pkg of vulnerablePackages) {
        if (pkgJson.includes(pkg.split('@')[0])) {
          hasVulnerablePackage = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'DEP-002',
      name: 'Known Vulnerable Packages',
      description: 'Package.json may contain known vulnerable packages',
      category: 'dependencies',
      severity: 'critical',
      passed: !hasVulnerablePackage,
      message: hasVulnerablePackage
        ? 'Potentially vulnerable package detected - run npm audit'
        : 'No known vulnerable packages in direct dependencies',
      fixable: false,
    });

    // DEP-003: Check for wildcard versions
    let hasWildcardVersions = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      const pkg = JSON.parse(pkgJson);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const [, version] of Object.entries(allDeps)) {
        if (version === '*' || version === 'latest') {
          hasWildcardVersions = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'DEP-003',
      name: 'Wildcard Dependency Versions',
      description: 'Package.json uses wildcard or latest versions',
      category: 'dependencies',
      severity: 'high',
      passed: !hasWildcardVersions,
      message: hasWildcardVersions
        ? 'Wildcard versions detected - pin dependencies for reproducible builds'
        : 'All dependency versions are properly specified',
      fixable: false,
    });

    // DEP-004: Check for npm scripts security
    let hasDangerousScripts = false;
    const dangerousScriptPatterns = ['curl | sh', 'wget | bash', 'eval(', '$(curl'];
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      const pkg = JSON.parse(pkgJson);
      if (pkg.scripts) {
        for (const [, script] of Object.entries(pkg.scripts)) {
          if (typeof script === 'string') {
            for (const pattern of dangerousScriptPatterns) {
              if (script.includes(pattern)) {
                hasDangerousScripts = true;
                break;
              }
            }
          }
        }
      }
    } catch {}

    findings.push({
      checkId: 'DEP-004',
      name: 'Dangerous npm Scripts',
      description: 'npm scripts contain potentially dangerous commands',
      category: 'dependencies',
      severity: 'critical',
      passed: !hasDangerousScripts,
      message: hasDangerousScripts
        ? 'Dangerous patterns in npm scripts (curl|sh, eval) - review carefully'
        : 'npm scripts appear safe',
      fixable: false,
    });

    return findings;
  }

  private async checkAuthSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // AUTH-001: Check for auth configuration
    let hasAuthConfig = false;
    const authIndicators = ['auth', 'authentication', 'passport', 'jwt', 'session'];

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      for (const indicator of authIndicators) {
        if (pkgJson.toLowerCase().includes(indicator)) {
          hasAuthConfig = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUTH-001',
      name: 'Authentication Configuration',
      description: 'No authentication library or configuration detected',
      category: 'authentication',
      severity: 'medium',
      passed: hasAuthConfig,
      message: hasAuthConfig
        ? 'Authentication configuration detected'
        : 'No authentication library detected - ensure endpoints are protected',
      fixable: false,
    });

    // AUTH-002: Check for rate limiting
    let hasRateLimiting = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasRateLimiting = pkgJson.includes('rate-limit') || pkgJson.includes('express-rate-limit') || pkgJson.includes('bottleneck');
    } catch {}

    findings.push({
      checkId: 'AUTH-002',
      name: 'Rate Limiting',
      description: 'No rate limiting library detected',
      category: 'authentication',
      severity: 'high',
      passed: hasRateLimiting,
      message: hasRateLimiting
        ? 'Rate limiting library detected'
        : 'No rate limiting detected - API may be vulnerable to abuse',
      fixable: false,
    });

    // AUTH-003: Check for session security
    let hasSecureSessions = false;
    const sessionIndicators = ['express-session', 'cookie-session', 'secure: true', 'httpOnly: true'];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            for (const indicator of sessionIndicators) {
              if (content.includes(indicator)) {
                hasSecureSessions = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUTH-003',
      name: 'Secure Session Configuration',
      description: 'Session security configuration not detected',
      category: 'authentication',
      severity: 'medium',
      passed: hasSecureSessions,
      message: hasSecureSessions
        ? 'Secure session configuration detected'
        : 'Ensure sessions use secure, httpOnly cookies',
      fixable: false,
    });

    // AUTH-004: Check for CORS configuration
    let hasCorsConfig = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasCorsConfig = pkgJson.includes('cors');
    } catch {}

    findings.push({
      checkId: 'AUTH-004',
      name: 'CORS Configuration',
      description: 'No CORS library detected',
      category: 'authentication',
      severity: 'medium',
      passed: hasCorsConfig,
      message: hasCorsConfig
        ? 'CORS library detected'
        : 'No CORS configuration detected - ensure cross-origin requests are properly handled',
      fixable: false,
    });

    return findings;
  }

  private async checkProcessSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // PROC-001: Check for Dockerfile security
    let hasSecureDockerfile = true;
    try {
      const dockerfile = await fs.readFile(path.join(targetDir, 'Dockerfile'), 'utf-8');
      if (dockerfile.includes('USER root') || !dockerfile.includes('USER ')) {
        hasSecureDockerfile = false;
      }
    } catch {
      // No Dockerfile, that's fine
    }

    findings.push({
      checkId: 'PROC-001',
      name: 'Container User',
      description: 'Dockerfile runs as root or has no USER directive',
      category: 'process',
      severity: 'high',
      passed: hasSecureDockerfile,
      message: hasSecureDockerfile
        ? 'Container runs as non-root user or no Dockerfile present'
        : 'Dockerfile runs as root - add USER directive for non-root user',
      fixable: false,
    });

    // PROC-002: Check for security headers middleware
    let hasSecurityHeaders = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasSecurityHeaders = pkgJson.includes('helmet') || pkgJson.includes('security-headers');
    } catch {}

    findings.push({
      checkId: 'PROC-002',
      name: 'Security Headers',
      description: 'No security headers middleware detected',
      category: 'process',
      severity: 'medium',
      passed: hasSecurityHeaders,
      message: hasSecurityHeaders
        ? 'Security headers middleware detected (helmet)'
        : 'Consider using helmet or similar for security headers',
      fixable: false,
    });

    // PROC-003: Check for input validation
    let hasInputValidation = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasInputValidation = pkgJson.includes('joi') || pkgJson.includes('zod') || pkgJson.includes('yup') || pkgJson.includes('class-validator');
    } catch {}

    findings.push({
      checkId: 'PROC-003',
      name: 'Input Validation',
      description: 'No input validation library detected',
      category: 'process',
      severity: 'high',
      passed: hasInputValidation,
      message: hasInputValidation
        ? 'Input validation library detected'
        : 'No input validation library found - validate all user inputs',
      fixable: false,
    });

    // PROC-004: Check for error handling
    let hasErrorHandling = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('try') && content.includes('catch')) {
              hasErrorHandling = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'PROC-004',
      name: 'Error Handling',
      description: 'No error handling patterns detected',
      category: 'process',
      severity: 'medium',
      passed: hasErrorHandling,
      message: hasErrorHandling
        ? 'Error handling patterns detected'
        : 'Ensure proper error handling to prevent information disclosure',
      fixable: false,
    });

    return findings;
  }

  private async checkClaudeExtended(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const claudeSettingsPath = path.join(targetDir, '.claude', 'settings.json');

    let claudeSettings: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(claudeSettingsPath, 'utf-8');
      claudeSettings = JSON.parse(content);
    } catch {}

    // CLAUDE-004: Check for deny rules
    const permissions = claudeSettings?.permissions as { deny?: string[] } | undefined;
    const hasDenyRules = permissions?.deny && permissions.deny.length > 0;

    findings.push({
      checkId: 'CLAUDE-004',
      name: 'Claude Deny Rules',
      description: 'No deny rules configured for Claude Code',
      category: 'claude-code',
      severity: 'medium',
      passed: hasDenyRules || !claudeSettings,
      message: hasDenyRules
        ? 'Claude Code has deny rules configured'
        : claudeSettings
          ? 'Consider adding deny rules to block dangerous operations'
          : 'No Claude settings file found',
      fixable: false,
    });

    // CLAUDE-005: Check for memory/context persistence
    const memorySettings = claudeSettings?.memory as { enabled?: boolean } | undefined;
    const hasMemoryEnabled = memorySettings?.enabled === true;

    findings.push({
      checkId: 'CLAUDE-005',
      name: 'Claude Memory Persistence',
      description: 'Claude memory persistence may store sensitive context',
      category: 'claude-code',
      severity: 'low',
      passed: !hasMemoryEnabled,
      message: hasMemoryEnabled
        ? 'Claude memory enabled - be aware sensitive data may persist'
        : 'Claude memory not explicitly enabled',
      fixable: false,
    });

    // CLAUDE-006: Check CLAUDE.md for sensitive instructions
    let hasSensitiveInstructions = false;
    const sensitivePatterns = ['never share', 'confidential', 'internal only', 'do not disclose'];

    try {
      const claudeMd = await fs.readFile(path.join(targetDir, 'CLAUDE.md'), 'utf-8');
      for (const pattern of sensitivePatterns) {
        if (claudeMd.toLowerCase().includes(pattern)) {
          hasSensitiveInstructions = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'CLAUDE-006',
      name: 'Sensitive Instructions in CLAUDE.md',
      description: 'CLAUDE.md may contain sensitive instructions that could be extracted',
      category: 'claude-code',
      severity: 'medium',
      passed: !hasSensitiveInstructions,
      message: hasSensitiveInstructions
        ? 'CLAUDE.md contains sensitive instructions - these may be extractable via prompt injection'
        : 'No obviously sensitive instructions detected in CLAUDE.md',
      fixable: false,
    });

    // CLAUDE-007: Check for tool timeout configuration
    const hasToolTimeout = (claudeSettings as Record<string, unknown>)?.toolTimeout !== undefined;

    findings.push({
      checkId: 'CLAUDE-007',
      name: 'Tool Timeout Configuration',
      description: 'No tool timeout configured for Claude operations',
      category: 'claude-code',
      severity: 'low',
      passed: hasToolTimeout || !claudeSettings,
      message: hasToolTimeout
        ? 'Tool timeout is configured'
        : claudeSettings
          ? 'Consider setting tool timeouts to prevent runaway operations'
          : 'No Claude settings found',
      fixable: false,
    });

    return findings;
  }

  private async checkMcpExtended(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(content);
    } catch {}

    // MCP-006: Check for request timeout
    const hasTimeout = (mcpConfig as Record<string, unknown>)?.timeout !== undefined;

    findings.push({
      checkId: 'MCP-006',
      name: 'MCP Request Timeout',
      description: 'No request timeout configured for MCP servers',
      category: 'mcp',
      severity: 'medium',
      passed: hasTimeout || !mcpConfig,
      message: hasTimeout
        ? 'MCP timeout is configured'
        : mcpConfig
          ? 'Consider setting request timeouts for MCP servers'
          : 'No MCP config found',
      fixable: false,
    });

    // MCP-007: Check for retry limits
    const hasRetryConfig = (mcpConfig as Record<string, unknown>)?.retries !== undefined;

    findings.push({
      checkId: 'MCP-007',
      name: 'MCP Retry Limits',
      description: 'No retry limits configured for MCP servers',
      category: 'mcp',
      severity: 'low',
      passed: hasRetryConfig || !mcpConfig,
      message: hasRetryConfig
        ? 'MCP retry limits configured'
        : mcpConfig
          ? 'Consider setting retry limits to prevent infinite loops'
          : 'No MCP config found',
      fixable: false,
    });

    // MCP-008: Check for localhost binding
    let allLocalhostBound = true;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[]; url?: string }>)) {
        if (server.url && !server.url.includes('localhost') && !server.url.includes('127.0.0.1')) {
          // Remote server is fine if using HTTPS
          continue;
        }
        if (server.args?.some((arg: string) => arg.includes('0.0.0.0'))) {
          allLocalhostBound = false;
        }
      }
    }

    findings.push({
      checkId: 'MCP-008',
      name: 'MCP Localhost Binding',
      description: 'MCP servers should bind to localhost only',
      category: 'mcp',
      severity: 'high',
      passed: allLocalhostBound,
      message: allLocalhostBound
        ? 'MCP servers properly bound to localhost'
        : 'Some MCP servers not bound to localhost - may be network accessible',
      fixable: false,
    });

    // MCP-009: Check for sensitive tool names
    const sensitiveTools = ['execute', 'shell', 'eval', 'system', 'exec', 'spawn'];
    let hasSensitiveTools = false;

    if (mcpConfig?.servers) {
      for (const [name] of Object.entries(mcpConfig.servers as Record<string, unknown>)) {
        for (const tool of sensitiveTools) {
          if (name.toLowerCase().includes(tool)) {
            hasSensitiveTools = true;
            break;
          }
        }
      }
    }

    findings.push({
      checkId: 'MCP-009',
      name: 'Sensitive MCP Tools',
      description: 'MCP configuration includes potentially dangerous tools',
      category: 'mcp',
      severity: 'high',
      passed: !hasSensitiveTools,
      message: hasSensitiveTools
        ? 'Sensitive tool names detected (shell, exec, eval) - ensure proper restrictions'
        : 'No obviously sensitive tool names in MCP config',
      fixable: false,
    });

    // MCP-010: Check for logging configuration
    let hasLogging = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args?.some((arg: string) => arg.includes('log') || arg.includes('verbose'))) {
          hasLogging = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'MCP-010',
      name: 'MCP Logging',
      description: 'MCP server logging configuration',
      category: 'mcp',
      severity: 'low',
      passed: true, // Informational
      message: hasLogging
        ? 'MCP logging appears to be configured - ensure sensitive data is not logged'
        : 'No explicit MCP logging configuration detected',
      fixable: false,
    });

    return findings;
  }

  private async checkNetworkExtended(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // NET-003: Check for HTTPS enforcement
    let hasHttpsEnforcement = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('https') || content.includes('SSL') || content.includes('TLS')) {
              hasHttpsEnforcement = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'NET-003',
      name: 'HTTPS Configuration',
      description: 'No HTTPS/TLS configuration detected',
      category: 'network',
      severity: 'high',
      passed: hasHttpsEnforcement,
      message: hasHttpsEnforcement
        ? 'HTTPS/TLS configuration detected'
        : 'No HTTPS configuration found - ensure production uses TLS',
      fixable: false,
    });

    // NET-004: Check for exposed debug endpoints
    let hasDebugEndpoints = false;
    const debugEndpoints = ['/debug', '/admin', '/metrics', '/health', '/status', '/__debug'];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            for (const endpoint of debugEndpoints) {
              if (content.includes(endpoint)) {
                hasDebugEndpoints = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'NET-004',
      name: 'Debug Endpoints',
      description: 'Debug or admin endpoints may be exposed',
      category: 'network',
      severity: 'medium',
      passed: !hasDebugEndpoints,
      message: hasDebugEndpoints
        ? 'Debug/admin endpoints detected - ensure they are protected or disabled in production'
        : 'No obvious debug endpoints found',
      fixable: false,
    });

    // NET-005: Check for WebSocket security
    let hasWebsocket = false;
    let hasWsAuth = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasWebsocket = pkgJson.includes('ws') || pkgJson.includes('socket.io') || pkgJson.includes('websocket');

      if (hasWebsocket) {
        const files = await fs.readdir(targetDir);
        for (const file of files) {
          if (file.endsWith('.ts') || file.endsWith('.js')) {
            try {
              const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
              if (content.includes('verifyClient') || content.includes('handleUpgrade') || (content.includes('connection') && content.includes('auth'))) {
                hasWsAuth = true;
                break;
              }
            } catch {}
          }
        }
      }
    } catch {}

    findings.push({
      checkId: 'NET-005',
      name: 'WebSocket Security',
      description: 'WebSocket connections may lack authentication',
      category: 'network',
      severity: 'high',
      passed: !hasWebsocket || hasWsAuth,
      message: !hasWebsocket
        ? 'No WebSocket usage detected'
        : hasWsAuth
          ? 'WebSocket authentication detected'
          : 'WebSocket without obvious authentication - ensure connections are verified',
      fixable: false,
    });

    // NET-006: Check for proxy configuration
    let hasProxyConfig = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasProxyConfig = pkgJson.includes('http-proxy') || pkgJson.includes('express-http-proxy');
    } catch {}

    if (hasProxyConfig) {
      findings.push({
        checkId: 'NET-006',
        name: 'Proxy Configuration',
        description: 'HTTP proxy detected - ensure proper access controls',
        category: 'network',
        severity: 'medium',
        passed: true, // Informational
        message: 'HTTP proxy library detected - verify SSRF protections are in place',
        fixable: false,
      });
    }

    return findings;
  }

  private async checkAPISecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // API-001: Check for API versioning
    let hasApiVersioning = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('/api/v1') || content.includes('/api/v2') || content.includes('version')) {
              hasApiVersioning = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'API-001',
      name: 'API Versioning',
      description: 'API versioning not detected',
      category: 'api',
      severity: 'low',
      passed: hasApiVersioning,
      message: hasApiVersioning
        ? 'API versioning pattern detected'
        : 'Consider implementing API versioning for backwards compatibility',
      fixable: false,
    });

    // API-002: Check for API documentation
    let hasApiDocs = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasApiDocs = pkgJson.includes('swagger') || pkgJson.includes('openapi') || pkgJson.includes('@apidevtools');
    } catch {}

    findings.push({
      checkId: 'API-002',
      name: 'API Documentation',
      description: 'No API documentation library detected',
      category: 'api',
      severity: 'low',
      passed: hasApiDocs,
      message: hasApiDocs
        ? 'API documentation library detected'
        : 'Consider adding OpenAPI/Swagger documentation',
      fixable: false,
    });

    // API-003: Check for API key in URL
    let hasKeyInUrl = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('apiKey=') || content.includes('api_key=') || content.includes('key=')) {
              if (content.includes('query') || content.includes('req.query')) {
                hasKeyInUrl = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'API-003',
      name: 'API Key in URL',
      description: 'API keys may be passed in URL query parameters',
      category: 'api',
      severity: 'high',
      passed: !hasKeyInUrl,
      message: hasKeyInUrl
        ? 'API key in URL pattern detected - use headers instead'
        : 'No obvious API key in URL patterns found',
      fixable: false,
    });

    // API-004: Check for response headers security
    let hasSecurityHeaders = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('X-Content-Type-Options') || content.includes('X-Frame-Options') || content.includes('Content-Security-Policy')) {
              hasSecurityHeaders = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'API-004',
      name: 'API Security Headers',
      description: 'Security headers not explicitly set',
      category: 'api',
      severity: 'medium',
      passed: hasSecurityHeaders,
      message: hasSecurityHeaders
        ? 'Security headers detected in responses'
        : 'Add security headers (X-Content-Type-Options, X-Frame-Options, CSP)',
      fixable: false,
    });

    return findings;
  }

  private async checkSecretManagement(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // SEC-001: Check for secret management tools
    let hasSecretManager = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasSecretManager = pkgJson.includes('vault') || pkgJson.includes('aws-sdk') || pkgJson.includes('dotenv-vault') || pkgJson.includes('1password');
    } catch {}

    findings.push({
      checkId: 'SEC-001',
      name: 'Secret Management',
      description: 'No secret management tool detected',
      category: 'secrets',
      severity: 'medium',
      passed: hasSecretManager,
      message: hasSecretManager
        ? 'Secret management capability detected'
        : 'Consider using a secret manager (Vault, AWS Secrets Manager, doppler)',
      fixable: false,
    });

    // SEC-002: Check for encryption library
    let hasEncryption = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasEncryption = pkgJson.includes('crypto') || pkgJson.includes('bcrypt') || pkgJson.includes('argon2') || pkgJson.includes('sodium');
    } catch {}

    findings.push({
      checkId: 'SEC-002',
      name: 'Encryption Library',
      description: 'No encryption library detected',
      category: 'secrets',
      severity: 'medium',
      passed: hasEncryption,
      message: hasEncryption
        ? 'Encryption library detected'
        : 'Consider using encryption for sensitive data (bcrypt, argon2)',
      fixable: false,
    });

    // SEC-003: Check for key rotation support
    let hasKeyRotation = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        try {
          const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
          if (content.includes('rotation') || content.includes('rotate') || content.includes('KEY_VERSION')) {
            hasKeyRotation = true;
            break;
          }
        } catch {}
      }
    } catch {}

    findings.push({
      checkId: 'SEC-003',
      name: 'Key Rotation Support',
      description: 'No key rotation mechanism detected',
      category: 'secrets',
      severity: 'low',
      passed: hasKeyRotation,
      message: hasKeyRotation
        ? 'Key rotation support detected'
        : 'Consider implementing key rotation for long-lived secrets',
      fixable: false,
    });

    // SEC-004: Check for hardcoded connection strings
    let hasHardcodedConnStr = false;
    const connPatterns = ['mongodb://', 'postgres://', 'mysql://', 'redis://', 'amqp://'];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            for (const pattern of connPatterns) {
              if (content.includes(pattern) && !content.includes('${') && !content.includes('process.env')) {
                hasHardcodedConnStr = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SEC-004',
      name: 'Hardcoded Connection Strings',
      description: 'Connection strings may be hardcoded',
      category: 'secrets',
      severity: 'critical',
      passed: !hasHardcodedConnStr,
      message: hasHardcodedConnStr
        ? 'Hardcoded connection strings detected - use environment variables'
        : 'No hardcoded connection strings found',
      fixable: false,
    });

    return findings;
  }

  private async checkIOSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // IO-001: Check for file upload handling
    let hasFileUpload = false;
    let hasUploadSecurity = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasFileUpload = pkgJson.includes('multer') || pkgJson.includes('formidable') || pkgJson.includes('busboy');

      if (hasFileUpload) {
        const files = await fs.readdir(targetDir);
        for (const file of files) {
          if (file.endsWith('.ts') || file.endsWith('.js')) {
            try {
              const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
              if (content.includes('fileFilter') || content.includes('limits') || content.includes('mimetype')) {
                hasUploadSecurity = true;
                break;
              }
            } catch {}
          }
        }
      }
    } catch {}

    findings.push({
      checkId: 'IO-001',
      name: 'File Upload Security',
      description: 'File upload without proper validation',
      category: 'io',
      severity: 'high',
      passed: !hasFileUpload || hasUploadSecurity,
      message: !hasFileUpload
        ? 'No file upload handling detected'
        : hasUploadSecurity
          ? 'File upload validation detected'
          : 'File upload without obvious validation - add file type/size limits',
      fixable: false,
    });

    // IO-002: Check for SQL/NoSQL injection protection
    let hasDbLibrary = false;
    let hasParameterization = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasDbLibrary = pkgJson.includes('pg') || pkgJson.includes('mysql') || pkgJson.includes('mongodb') || pkgJson.includes('prisma') || pkgJson.includes('sequelize');

      if (hasDbLibrary) {
        // ORMs and query builders generally handle parameterization
        hasParameterization = pkgJson.includes('prisma') || pkgJson.includes('sequelize') || pkgJson.includes('typeorm') || pkgJson.includes('knex');
      }
    } catch {}

    findings.push({
      checkId: 'IO-002',
      name: 'Query Parameterization',
      description: 'Database queries may be vulnerable to injection',
      category: 'io',
      severity: 'critical',
      passed: !hasDbLibrary || hasParameterization,
      message: !hasDbLibrary
        ? 'No database library detected'
        : hasParameterization
          ? 'ORM/query builder detected - provides parameterization'
          : 'Raw database driver detected - ensure parameterized queries are used',
      fixable: false,
    });

    // IO-003: Check for XSS protection
    let hasXssProtection = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasXssProtection = pkgJson.includes('xss') || pkgJson.includes('sanitize') || pkgJson.includes('DOMPurify') || pkgJson.includes('helmet');
    } catch {}

    findings.push({
      checkId: 'IO-003',
      name: 'XSS Protection',
      description: 'No XSS protection library detected',
      category: 'io',
      severity: 'high',
      passed: hasXssProtection,
      message: hasXssProtection
        ? 'XSS protection library detected'
        : 'No XSS protection library found - sanitize user input before rendering',
      fixable: false,
    });

    // IO-004: Check for path traversal protection
    let hasPathTraversal = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            // Check for dangerous patterns
            if (content.includes('req.params') && content.includes('readFile')) {
              if (!content.includes('path.normalize') && !content.includes('path.resolve')) {
                hasPathTraversal = true;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'IO-004',
      name: 'Path Traversal Protection',
      description: 'Potential path traversal vulnerability',
      category: 'io',
      severity: 'high',
      passed: !hasPathTraversal,
      message: hasPathTraversal
        ? 'Potential path traversal detected - use path.resolve/normalize'
        : 'No obvious path traversal vulnerabilities found',
      fixable: false,
    });

    return findings;
  }

  /**
   * Prompt injection defense checks
   */
  private async checkPromptSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // PROMPT-001: Check for system prompt boundary markers
    let hasPromptBoundaries = false;
    const claudeMdPath = path.join(targetDir, 'CLAUDE.md');
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasPromptBoundaries =
        content.includes('SYSTEM:') ||
        content.includes('USER:') ||
        content.includes('---') ||
        content.includes('###') ||
        content.toLowerCase().includes('do not follow instructions') ||
        content.toLowerCase().includes('ignore attempts to');
    } catch {}

    findings.push({
      checkId: 'PROMPT-001',
      name: 'Prompt Boundary Markers',
      description: 'System prompts should have clear boundary markers to prevent injection',
      category: 'prompt-security',
      severity: 'high',
      passed: hasPromptBoundaries,
      message: hasPromptBoundaries
        ? 'Prompt boundaries detected in CLAUDE.md'
        : 'Consider adding prompt boundary markers to prevent injection attacks',
      fixable: false,
    });

    // PROMPT-002: Check for injection defense instructions
    let hasInjectionDefense = false;
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasInjectionDefense =
        content.toLowerCase().includes('injection') ||
        content.toLowerCase().includes('malicious') ||
        content.toLowerCase().includes('untrusted') ||
        content.toLowerCase().includes('sanitize') ||
        content.toLowerCase().includes('validate input');
    } catch {}

    findings.push({
      checkId: 'PROMPT-002',
      name: 'Injection Defense Instructions',
      description: 'System prompts should include injection defense guidance',
      category: 'prompt-security',
      severity: 'medium',
      passed: hasInjectionDefense,
      message: hasInjectionDefense
        ? 'Injection defense instructions found'
        : 'Consider adding injection defense instructions to system prompts',
      fixable: false,
    });

    // PROMPT-003: Check for output constraints
    let hasOutputConstraints = false;
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasOutputConstraints =
        content.toLowerCase().includes('never output') ||
        content.toLowerCase().includes('do not reveal') ||
        content.toLowerCase().includes('do not disclose') ||
        content.toLowerCase().includes('keep confidential') ||
        content.toLowerCase().includes('do not share');
    } catch {}

    findings.push({
      checkId: 'PROMPT-003',
      name: 'Output Confidentiality Rules',
      description: 'System prompts should define output confidentiality constraints',
      category: 'prompt-security',
      severity: 'medium',
      passed: hasOutputConstraints,
      message: hasOutputConstraints
        ? 'Output confidentiality rules defined'
        : 'Consider defining what information should not be disclosed',
      fixable: false,
    });

    // PROMPT-004: Check for role confusion protection
    let hasRoleProtection = false;
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasRoleProtection =
        content.toLowerCase().includes('you are') ||
        content.toLowerCase().includes('your role') ||
        content.toLowerCase().includes('as an assistant') ||
        content.toLowerCase().includes('maintain your role');
    } catch {}

    findings.push({
      checkId: 'PROMPT-004',
      name: 'Role Definition Protection',
      description: 'System prompts should clearly define the AI role to prevent confusion attacks',
      category: 'prompt-security',
      severity: 'low',
      passed: hasRoleProtection,
      message: hasRoleProtection
        ? 'Role definition found in prompts'
        : 'Consider clearly defining the AI role to prevent role confusion attacks',
      fixable: false,
    });

    return findings;
  }

  /**
   * Input validation and sanitization checks
   */
  private async checkInputValidation(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // INJ-001: Check for input validation in MCP handlers
    let hasInputValidation = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('zod') ||
              content.includes('joi') ||
              content.includes('yup') ||
              content.includes('validate(') ||
              content.includes('sanitize(') ||
              content.includes('schema.')
            ) {
              hasInputValidation = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'INJ-001',
      name: 'Input Validation Library',
      description: 'Applications should use schema validation for inputs',
      category: 'input-validation',
      severity: 'high',
      passed: hasInputValidation,
      message: hasInputValidation
        ? 'Input validation library detected'
        : 'Consider using zod, joi, or similar for input validation',
      fixable: false,
    });

    // INJ-002: Check for XSS protection patterns
    let hasXssProtection = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('escapeHtml') ||
              content.includes('sanitizeHtml') ||
              content.includes('DOMPurify') ||
              content.includes('xss(') ||
              content.includes('encode(')
            ) {
              hasXssProtection = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'INJ-002',
      name: 'XSS Protection',
      description: 'Output should be properly escaped to prevent XSS',
      category: 'input-validation',
      severity: 'high',
      passed: hasXssProtection,
      message: hasXssProtection
        ? 'XSS protection patterns detected'
        : 'Consider implementing output escaping for user-facing content',
      fixable: false,
    });

    // INJ-003: Check for SQL injection protection
    let hasSqlProtection = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('parameterized') ||
              content.includes('prepared') ||
              content.includes('$1') ||
              content.includes('?') && content.includes('query(') ||
              content.includes('prisma') ||
              content.includes('knex') ||
              content.includes('sequelize')
            ) {
              hasSqlProtection = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'INJ-003',
      name: 'SQL Injection Protection',
      description: 'Database queries should use parameterized statements',
      category: 'input-validation',
      severity: 'critical',
      passed: hasSqlProtection,
      message: hasSqlProtection
        ? 'Parameterized queries or ORM detected'
        : 'Ensure all database queries use parameterized statements',
      fixable: false,
    });

    // INJ-004: Check for command injection protection
    let hasCmdProtection = false;
    try {
      const files = await fs.readdir(targetDir);
      let hasExec = false;
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('exec(') || content.includes('spawn(')) {
              hasExec = true;
              if (
                content.includes('execFile') ||
                content.includes('shell: false') ||
                content.includes('shellEscape') ||
                !content.includes('${')
              ) {
                hasCmdProtection = true;
              }
            }
          } catch {}
        }
      }
      if (!hasExec) hasCmdProtection = true; // No exec calls found
    } catch {
      hasCmdProtection = true;
    }

    findings.push({
      checkId: 'INJ-004',
      name: 'Command Injection Protection',
      description: 'Shell commands should use safe execution patterns',
      category: 'input-validation',
      severity: 'critical',
      passed: hasCmdProtection,
      message: hasCmdProtection
        ? 'Safe command execution patterns detected or no shell commands found'
        : 'Use execFile instead of exec, or disable shell interpolation',
      fixable: false,
    });

    return findings;
  }

  /**
   * Rate limiting and throttling checks
   */
  private async checkRateLimiting(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // RATE-001: Check for rate limiting configuration
    let hasRateLimiting = false;
    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      hasRateLimiting =
        'express-rate-limit' in deps ||
        'rate-limiter-flexible' in deps ||
        'bottleneck' in deps ||
        '@upstash/ratelimit' in deps;
    } catch {}

    findings.push({
      checkId: 'RATE-001',
      name: 'Rate Limiting Configuration',
      description: 'API endpoints should have rate limiting',
      category: 'rate-limiting',
      severity: 'medium',
      passed: hasRateLimiting,
      message: hasRateLimiting
        ? 'Rate limiting library detected'
        : 'Consider implementing rate limiting to prevent abuse',
      fixable: false,
    });

    // RATE-002: Check for retry/backoff patterns
    let hasBackoff = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('retry') ||
              content.includes('backoff') ||
              content.includes('exponential') ||
              content.includes('p-retry')
            ) {
              hasBackoff = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'RATE-002',
      name: 'Retry with Backoff',
      description: 'External calls should implement exponential backoff',
      category: 'rate-limiting',
      severity: 'low',
      passed: hasBackoff,
      message: hasBackoff
        ? 'Retry/backoff patterns detected'
        : 'Consider implementing exponential backoff for external calls',
      fixable: false,
    });

    // RATE-003: Check for timeout configurations
    let hasTimeouts = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('timeout') ||
              content.includes('Timeout') ||
              content.includes('TIMEOUT')
            ) {
              hasTimeouts = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'RATE-003',
      name: 'Timeout Configuration',
      description: 'Operations should have appropriate timeouts',
      category: 'rate-limiting',
      severity: 'medium',
      passed: hasTimeouts,
      message: hasTimeouts
        ? 'Timeout configurations detected'
        : 'Consider setting timeouts for external calls and long-running operations',
      fixable: false,
    });

    // RATE-004: Check for concurrent request limiting
    let hasConcurrencyLimit = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('p-limit') ||
              content.includes('semaphore') ||
              content.includes('concurrency') ||
              content.includes('maxConcurrent')
            ) {
              hasConcurrencyLimit = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'RATE-004',
      name: 'Concurrency Limits',
      description: 'Concurrent operations should be limited',
      category: 'rate-limiting',
      severity: 'low',
      passed: hasConcurrencyLimit,
      message: hasConcurrencyLimit
        ? 'Concurrency limiting detected'
        : 'Consider limiting concurrent operations to prevent resource exhaustion',
      fixable: false,
    });

    return findings;
  }

  /**
   * Session and timeout security checks
   */
  private async checkSessionSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // SESSION-001: Check for secure session configuration
    let hasSecureSessions = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('httpOnly') ||
              content.includes('secure: true') ||
              content.includes('sameSite')
            ) {
              hasSecureSessions = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SESSION-001',
      name: 'Secure Cookie Settings',
      description: 'Session cookies should have secure flags',
      category: 'session-security',
      severity: 'high',
      passed: hasSecureSessions,
      message: hasSecureSessions
        ? 'Secure cookie flags detected'
        : 'Set httpOnly, secure, and sameSite on session cookies',
      fixable: false,
    });

    // SESSION-002: Check for session expiry
    let hasSessionExpiry = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('maxAge') ||
              content.includes('expiresIn') ||
              content.includes('ttl') ||
              content.includes('sessionTimeout')
            ) {
              hasSessionExpiry = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SESSION-002',
      name: 'Session Expiry',
      description: 'Sessions should have appropriate expiry times',
      category: 'session-security',
      severity: 'medium',
      passed: hasSessionExpiry,
      message: hasSessionExpiry
        ? 'Session expiry configuration detected'
        : 'Configure appropriate session expiry times',
      fixable: false,
    });

    // SESSION-003: Check for CSRF protection
    let hasCsrfProtection = false;
    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      hasCsrfProtection = 'csurf' in deps || 'csrf' in deps || '@fastify/csrf-protection' in deps;
    } catch {}

    findings.push({
      checkId: 'SESSION-003',
      name: 'CSRF Protection',
      description: 'Forms should have CSRF protection',
      category: 'session-security',
      severity: 'high',
      passed: hasCsrfProtection,
      message: hasCsrfProtection
        ? 'CSRF protection library detected'
        : 'Consider implementing CSRF protection for state-changing operations',
      fixable: false,
    });

    // SESSION-004: Check for secure token storage
    let hasSecureStorage = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('keytar') ||
              content.includes('secure-store') ||
              content.includes('keychain') ||
              content.includes('credential-store')
            ) {
              hasSecureStorage = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SESSION-004',
      name: 'Secure Token Storage',
      description: 'Tokens should be stored securely',
      category: 'session-security',
      severity: 'medium',
      passed: hasSecureStorage,
      message: hasSecureStorage
        ? 'Secure token storage detected'
        : 'Consider using secure storage for sensitive tokens',
      fixable: false,
    });

    return findings;
  }

  /**
   * Data encryption checks
   */
  private async checkEncryption(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // ENCRYPT-001: Check for encryption at rest
    let hasEncryption = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('crypto') ||
              content.includes('encrypt') ||
              content.includes('aes-') ||
              content.includes('sodium')
            ) {
              hasEncryption = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-001',
      name: 'Encryption Implementation',
      description: 'Sensitive data should be encrypted at rest',
      category: 'encryption',
      severity: 'high',
      passed: hasEncryption,
      message: hasEncryption
        ? 'Encryption implementation detected'
        : 'Consider encrypting sensitive data at rest',
      fixable: false,
    });

    // ENCRYPT-002: Check for secure hashing
    let hasSecureHashing = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('bcrypt') ||
              content.includes('argon2') ||
              content.includes('scrypt') ||
              content.includes('pbkdf2')
            ) {
              hasSecureHashing = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-002',
      name: 'Secure Password Hashing',
      description: 'Passwords should use secure hashing algorithms',
      category: 'encryption',
      severity: 'critical',
      passed: hasSecureHashing,
      message: hasSecureHashing
        ? 'Secure hashing algorithm detected (bcrypt/argon2/scrypt)'
        : 'Use bcrypt, argon2, or scrypt for password hashing',
      fixable: false,
    });

    // ENCRYPT-003: Check for weak algorithms
    let hasWeakAlgorithms = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('md5') ||
              content.includes('sha1') ||
              content.includes("'des'") ||
              content.includes('"des"')
            ) {
              hasWeakAlgorithms = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-003',
      name: 'Weak Cryptographic Algorithms',
      description: 'Avoid using weak cryptographic algorithms',
      category: 'encryption',
      severity: 'high',
      passed: !hasWeakAlgorithms,
      message: hasWeakAlgorithms
        ? 'Weak algorithms detected (MD5/SHA1/DES) - use SHA-256+ and AES'
        : 'No weak cryptographic algorithms detected',
      fixable: false,
    });

    // ENCRYPT-004: Check for TLS configuration
    let hasTlsConfig = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('https') ||
              content.includes('tls') ||
              content.includes('ssl') ||
              content.includes('rejectUnauthorized')
            ) {
              hasTlsConfig = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-004',
      name: 'TLS Configuration',
      description: 'Communications should use TLS',
      category: 'encryption',
      severity: 'high',
      passed: hasTlsConfig,
      message: hasTlsConfig
        ? 'TLS/HTTPS configuration detected'
        : 'Ensure all communications use TLS',
      fixable: false,
    });

    return findings;
  }

  /**
   * Audit trail and logging security checks
   */
  private async checkAuditTrail(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // AUDIT-001: Check for audit logging
    let hasAuditLogging = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('audit') ||
              content.includes('winston') ||
              content.includes('pino') ||
              content.includes('bunyan')
            ) {
              hasAuditLogging = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUDIT-001',
      name: 'Audit Logging',
      description: 'Security-relevant events should be logged',
      category: 'audit',
      severity: 'medium',
      passed: hasAuditLogging,
      message: hasAuditLogging
        ? 'Audit logging implementation detected'
        : 'Consider implementing audit logging for security events',
      fixable: false,
    });

    // AUDIT-002: Check for log rotation
    let hasLogRotation = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('rotate') ||
              content.includes('maxFiles') ||
              content.includes('maxSize')
            ) {
              hasLogRotation = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUDIT-002',
      name: 'Log Rotation',
      description: 'Logs should have rotation configured',
      category: 'audit',
      severity: 'low',
      passed: hasLogRotation,
      message: hasLogRotation
        ? 'Log rotation configuration detected'
        : 'Consider configuring log rotation to manage disk space',
      fixable: false,
    });

    // AUDIT-003: Check for error tracking
    let hasErrorTracking = false;
    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      hasErrorTracking = '@sentry/node' in deps || 'bugsnag' in deps || 'rollbar' in deps;
    } catch {}

    findings.push({
      checkId: 'AUDIT-003',
      name: 'Error Tracking',
      description: 'Errors should be tracked for monitoring',
      category: 'audit',
      severity: 'low',
      passed: hasErrorTracking,
      message: hasErrorTracking
        ? 'Error tracking service detected'
        : 'Consider using an error tracking service for production',
      fixable: false,
    });

    // AUDIT-004: Check for no sensitive data in logs
    let hasLogSanitization = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('redact') ||
              content.includes('mask') ||
              content.includes('sanitize')
            ) {
              hasLogSanitization = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUDIT-004',
      name: 'Log Sanitization',
      description: 'Sensitive data should be redacted from logs',
      category: 'audit',
      severity: 'high',
      passed: hasLogSanitization,
      message: hasLogSanitization
        ? 'Log sanitization patterns detected'
        : 'Consider redacting sensitive data (passwords, tokens) from logs',
      fixable: false,
    });

    return findings;
  }

  /**
   * Process isolation and sandboxing checks
   */
  private async checkSandboxing(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // SANDBOX-001: Check for Docker/container usage
    let hasContainerization = false;
    try {
      await fs.access(path.join(targetDir, 'Dockerfile'));
      hasContainerization = true;
    } catch {}
    try {
      await fs.access(path.join(targetDir, 'docker-compose.yml'));
      hasContainerization = true;
    } catch {}
    try {
      await fs.access(path.join(targetDir, 'docker-compose.yaml'));
      hasContainerization = true;
    } catch {}

    findings.push({
      checkId: 'SANDBOX-001',
      name: 'Container Isolation',
      description: 'Applications should run in isolated containers',
      category: 'sandboxing',
      severity: 'medium',
      passed: hasContainerization,
      message: hasContainerization
        ? 'Container configuration detected'
        : 'Consider running in Docker containers for isolation',
      fixable: false,
    });

    // SANDBOX-002: Check for non-root execution
    let hasNonRootConfig = false;
    try {
      const dockerPath = path.join(targetDir, 'Dockerfile');
      const content = await fs.readFile(dockerPath, 'utf-8');
      hasNonRootConfig = content.includes('USER ') && !content.includes('USER root');
    } catch {}

    findings.push({
      checkId: 'SANDBOX-002',
      name: 'Non-Root Execution',
      description: 'Containers should not run as root',
      category: 'sandboxing',
      severity: 'high',
      passed: hasNonRootConfig,
      message: hasNonRootConfig
        ? 'Non-root user configured in Dockerfile'
        : 'Configure containers to run as non-root user',
      fixable: false,
    });

    // SANDBOX-003: Check for resource limits
    let hasResourceLimits = false;
    try {
      const composePath = path.join(targetDir, 'docker-compose.yml');
      const content = await fs.readFile(composePath, 'utf-8');
      hasResourceLimits = content.includes('mem_limit') || content.includes('cpus') || content.includes('deploy:');
    } catch {}
    try {
      const composePath = path.join(targetDir, 'docker-compose.yaml');
      const content = await fs.readFile(composePath, 'utf-8');
      hasResourceLimits = content.includes('mem_limit') || content.includes('cpus') || content.includes('deploy:');
    } catch {}

    findings.push({
      checkId: 'SANDBOX-003',
      name: 'Resource Limits',
      description: 'Containers should have resource limits',
      category: 'sandboxing',
      severity: 'medium',
      passed: hasResourceLimits,
      message: hasResourceLimits
        ? 'Resource limits configured'
        : 'Consider setting CPU and memory limits for containers',
      fixable: false,
    });

    // SANDBOX-004: Check for read-only filesystem
    let hasReadOnlyFs = false;
    try {
      const composePath = path.join(targetDir, 'docker-compose.yml');
      const content = await fs.readFile(composePath, 'utf-8');
      hasReadOnlyFs = content.includes('read_only: true');
    } catch {}

    findings.push({
      checkId: 'SANDBOX-004',
      name: 'Read-Only Filesystem',
      description: 'Containers should use read-only filesystem where possible',
      category: 'sandboxing',
      severity: 'low',
      passed: hasReadOnlyFs,
      message: hasReadOnlyFs
        ? 'Read-only filesystem configured'
        : 'Consider using read-only filesystem for containers',
      fixable: false,
    });

    return findings;
  }

  /**
   * MCP tool permission boundary checks
   */
  private async checkToolBoundaries(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(content);
    } catch {}

    // TOOL-001: Check for tool whitelisting
    let hasToolWhitelist = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { allowedTools?: string[] }>)) {
        if (server.allowedTools && server.allowedTools.length > 0) {
          hasToolWhitelist = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'TOOL-001',
      name: 'Tool Whitelisting',
      description: 'MCP servers should have explicit tool whitelists',
      category: 'tool-boundaries',
      severity: 'high',
      passed: hasToolWhitelist,
      message: hasToolWhitelist
        ? 'Tool whitelisting configured'
        : 'Configure allowedTools to restrict MCP server capabilities',
      fixable: false,
    });

    // TOOL-002: Check for resource constraints
    let hasResourceConstraints = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { maxTokens?: number; timeout?: number }>)) {
        if (server.maxTokens || server.timeout) {
          hasResourceConstraints = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'TOOL-002',
      name: 'Tool Resource Constraints',
      description: 'MCP tools should have resource constraints',
      category: 'tool-boundaries',
      severity: 'medium',
      passed: hasResourceConstraints,
      message: hasResourceConstraints
        ? 'Resource constraints configured'
        : 'Consider setting maxTokens and timeout for MCP tools',
      fixable: false,
    });

    // TOOL-003: Check for dangerous tool usage
    let hasDangerousTools = false;
    if (mcpConfig?.servers) {
      const dangerousTools = ['shell', 'exec', 'system', 'eval', 'run_command'];
      for (const [name] of Object.entries(mcpConfig.servers as Record<string, unknown>)) {
        for (const dangerous of dangerousTools) {
          if (name.toLowerCase().includes(dangerous)) {
            hasDangerousTools = true;
            break;
          }
        }
      }
    }

    findings.push({
      checkId: 'TOOL-003',
      name: 'Dangerous Tool Detection',
      description: 'Identify potentially dangerous MCP tools',
      category: 'tool-boundaries',
      severity: 'high',
      passed: !hasDangerousTools,
      message: hasDangerousTools
        ? 'Potentially dangerous tools detected (shell/exec) - ensure proper restrictions'
        : 'No obvious dangerous tools detected',
      fixable: false,
    });

    // TOOL-004: Check for tool confirmation requirements
    let hasConfirmation = false;
    try {
      const claudePath = path.join(targetDir, 'CLAUDE.md');
      const content = await fs.readFile(claudePath, 'utf-8');
      hasConfirmation =
        content.toLowerCase().includes('confirm') ||
        content.toLowerCase().includes('approval') ||
        content.toLowerCase().includes('ask before');
    } catch {}

    findings.push({
      checkId: 'TOOL-004',
      name: 'Tool Confirmation Requirements',
      description: 'Dangerous operations should require confirmation',
      category: 'tool-boundaries',
      severity: 'medium',
      passed: hasConfirmation,
      message: hasConfirmation
        ? 'Tool confirmation instructions detected'
        : 'Consider requiring confirmation for destructive operations',
      fixable: false,
    });

    return findings;
  }

  private calculateScore(findings: SecurityFinding[]): {
    score: number;
    maxScore: number;
  } {
    let score = 100;
    let maxDeduction = 0;

    for (const finding of findings) {
      const weight = SEVERITY_WEIGHTS[finding.severity];
      maxDeduction += weight;

      if (!finding.passed && !finding.fixed) {
        score -= weight;
      }
    }

    // Normalize to 0-100
    score = Math.max(0, score);
    const maxScore = 100;

    return { score, maxScore };
  }

  /**
   * Create a backup of files that may be modified during auto-fix
   */
  private async createBackup(targetDir: string): Promise<string> {
    const timestamp = new Date()
      .toISOString()
      .replace(/[T:]/g, '-')
      .replace(/\..+/, '')
      .replace(/-/g, (m, i) => (i < 10 ? '-' : ''));

    // Format: YYYY-MM-DD-HHMMSS
    const formattedTimestamp = new Date()
      .toISOString()
      .slice(0, 19)
      .replace('T', '-')
      .replace(/:/g, '');

    const backupDir = path.join(targetDir, '.hackmyagent-backup', formattedTimestamp);

    // Create backup directory
    await fs.mkdir(backupDir, { recursive: true });

    // Create manifest to track what existed before
    const manifest: { existingFiles: string[]; createdFiles: string[] } = {
      existingFiles: [],
      createdFiles: [],
    };

    // Backup each file that exists
    for (const file of HardeningScanner.BACKUP_FILES) {
      const sourcePath = path.join(targetDir, file);
      try {
        await fs.access(sourcePath);
        // File exists, back it up
        const destPath = path.join(backupDir, file);
        await fs.mkdir(path.dirname(destPath), { recursive: true });
        await fs.copyFile(sourcePath, destPath);
        manifest.existingFiles.push(file);
      } catch {
        // File doesn't exist, track it for rollback (may be created)
        manifest.createdFiles.push(file);
      }
    }

    // Save manifest
    await fs.writeFile(
      path.join(backupDir, '.manifest.json'),
      JSON.stringify(manifest, null, 2)
    );

    return backupDir;
  }

  /**
   * Rollback to the most recent backup
   */
  async rollback(targetDir: string): Promise<void> {
    const backupBaseDir = path.join(targetDir, '.hackmyagent-backup');

    // Check if backup directory exists
    try {
      await fs.access(backupBaseDir);
    } catch {
      throw new Error('No backup found. Cannot rollback.');
    }

    // Find the most recent backup
    const backups = await fs.readdir(backupBaseDir);
    const sortedBackups = backups
      .filter((b) => !b.startsWith('.'))
      .sort()
      .reverse();

    if (sortedBackups.length === 0) {
      throw new Error('No backup found. Cannot rollback.');
    }

    const latestBackup = sortedBackups[0];
    const backupDir = path.join(backupBaseDir, latestBackup);

    // Read manifest
    let manifest: { existingFiles: string[]; createdFiles: string[] };
    try {
      const manifestContent = await fs.readFile(
        path.join(backupDir, '.manifest.json'),
        'utf-8'
      );
      manifest = JSON.parse(manifestContent);
    } catch {
      throw new Error('Backup manifest is corrupted. Cannot rollback.');
    }

    // Restore existing files from backup
    for (const file of manifest.existingFiles) {
      const sourcePath = path.join(backupDir, file);
      const destPath = path.join(targetDir, file);
      try {
        await fs.copyFile(sourcePath, destPath);
      } catch (err) {
        // Continue with other files
      }
    }

    // Remove files that were created during auto-fix
    for (const file of manifest.createdFiles) {
      const filePath = path.join(targetDir, file);
      try {
        await fs.unlink(filePath);
      } catch {
        // File may not exist, that's OK
      }
    }

    // Remove the used backup
    await fs.rm(backupDir, { recursive: true, force: true });
  }
}
