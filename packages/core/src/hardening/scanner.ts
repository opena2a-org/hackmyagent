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
}

// Patterns for detecting exposed credentials
const CREDENTIAL_PATTERNS = [
  { name: 'ANTHROPIC_API_KEY', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{6,}/ },
  { name: 'OPENAI_API_KEY', pattern: /sk-proj-[a-zA-Z0-9]{6,}/ },
  { name: 'OPENAI_API_KEY', pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: 'AWS_ACCESS_KEY', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS_SECRET_KEY', pattern: /[a-zA-Z0-9/+=]{40}/ },
  { name: 'GITHUB_TOKEN', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GITHUB_TOKEN', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
  { name: 'SLACK_TOKEN', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/ },
  { name: 'DISCORD_TOKEN', pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/ },
];

// Severity weights for score calculation
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

export class HardeningScanner {
  async scan(options: ScanOptions): Promise<ScanResult> {
    const { targetDir, autoFix = false } = options;

    // Detect platform
    const platform = await this.detectPlatform(targetDir);

    // Run all checks
    const findings: SecurityFinding[] = [];

    // Credential exposure checks
    const credFindings = await this.checkCredentialExposure(targetDir, autoFix);
    findings.push(...credFindings);

    // CLAUDE.md specific checks
    const claudeFindings = await this.checkClaudeMd(targetDir, autoFix);
    findings.push(...claudeFindings);

    // MCP configuration checks
    const mcpFindings = await this.checkMcpConfig(targetDir, autoFix);
    findings.push(...mcpFindings);

    // File permission checks
    const permFindings = await this.checkFilePermissions(targetDir, autoFix);
    findings.push(...permFindings);

    // Calculate score
    const { score, maxScore } = this.calculateScore(findings);

    return {
      timestamp: new Date(),
      platform,
      findings,
      score,
      maxScore,
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

    // Files to check for credentials
    const filesToCheck = [
      'config.json',
      'config.yaml',
      'config.yml',
      '.env',
      '.env.local',
      'mcp.json',
      'CLAUDE.md',
      'settings.json',
    ];

    for (const filename of filesToCheck) {
      const filePath = path.join(targetDir, filename);
      try {
        const content = await fs.readFile(filePath, 'utf-8');

        for (const { name, pattern } of CREDENTIAL_PATTERNS) {
          if (pattern.test(content)) {
            // Check if it's an env var reference (not actual key)
            if (!content.includes('${') || !content.includes(name)) {
              exposedKeys.push(name);
            }
          }
        }
      } catch {
        // File doesn't exist, skip
      }
    }

    const passed = exposedKeys.length === 0;
    findings.push({
      checkId: 'CRED-001',
      name: 'Exposed API Keys',
      description: 'API keys or secrets found in plaintext configuration files',
      category: 'credentials',
      severity: 'critical',
      passed,
      message: passed
        ? 'No exposed API keys detected'
        : `Found exposed credentials: ${[...new Set(exposedKeys)].join(', ')}`,
      fixable: true,
      fixed: false,
      details: passed ? undefined : { keys: [...new Set(exposedKeys)] },
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

      if (config.servers) {
        for (const [name, server] of Object.entries(config.servers as Record<string, { command?: string; args?: string[] }>)) {
          // Check for root filesystem access
          if (
            server.args?.includes('/') ||
            server.args?.includes('~') ||
            server.args?.some((arg: string) => arg === '/' || arg === '~')
          ) {
            hasRootAccess = true;
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

      findings.push({
        checkId: 'MCP-001',
        name: 'MCP Root Filesystem Access',
        description: 'MCP server configured with root or home directory access',
        category: 'mcp',
        severity: 'high',
        passed: !hasRootAccess,
        message: hasRootAccess
          ? 'MCP server has dangerous filesystem access (/ or ~)'
          : 'MCP filesystem access is scoped appropriately',
        fixable: false,
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
        fixable: false,
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
}
