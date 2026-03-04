/**
 * Hardening Scanner
 * Scans for security issues and optionally auto-fixes them
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import type { ScanResult, SecurityFinding, Severity, ProjectType } from './security-check';
import { StructuralAnalyzer, toSecurityFindings, LLMAnalyzer } from '../semantic';

/**
 * Defines which checks apply to which project types
 * Key: check ID prefix or full ID
 * Value: array of project types this check applies to
 *
 * If a check ID is not in this map, it applies to 'all' project types
 */
const CHECK_PROJECT_TYPES: Record<string, ProjectType[]> = {
  // Core security checks - apply to all projects
  'CRED-': ['all'], // Credential exposure - always critical
  'GIT-': ['all'], // Git security - always important
  'PERM-': ['all'], // File permissions - always important
  'DEP-': ['all'], // Dependencies - always important

  // Environment checks - API/webapp mostly
  'ENV-': ['webapp', 'api', 'mcp'],

  // AI-specific checks - apply to MCP servers and AI-integrated projects
  'CLAUDE-': ['all'], // Claude-specific (if files exist)
  'MCP-': ['mcp'], // MCP configuration - only MCP servers
  'PROMPT-': ['mcp', 'api'], // Prompt injection - MCP and APIs
  'TOOL-': ['mcp'], // MCP tool boundaries

  // Web-specific checks - only for web apps and APIs
  'AUTH-': ['webapp', 'api'], // Authentication/authorization
  'SESSION-': ['webapp', 'api'], // Session management
  'NET-': ['webapp', 'api'], // Network security (HTTPS, etc.)
  'IO-': ['webapp', 'api'], // Input/output (XSS, etc.)

  // OpenClaw-specific checks
  'SKILL-': ['openclaw', 'mcp'], // Skill file security
  'HEARTBEAT-': ['openclaw'], // Heartbeat/periodic task security
  'GATEWAY-': ['openclaw'], // Gateway configuration security
  'CONFIG-': ['openclaw', 'mcp'], // Configuration file security
  'SUPPLY-': ['openclaw', 'mcp'], // Supply chain security
  'CVE-': ['openclaw'], // CVE-specific detection
  'API-': ['api'], // API security headers
  'RATE-': ['webapp', 'api'], // Rate limiting
  'PROC-': ['webapp', 'api'], // Process security (headers, etc.)

  // Database/encryption - only for apps with data storage
  'INJ-': ['webapp', 'api'], // SQL injection, input validation
  'ENCRYPT-': ['webapp', 'api'], // Encryption, password hashing

  // Logging/audit - servers and MCP
  'LOG-': ['webapp', 'api', 'mcp'],
  'AUDIT-': ['webapp', 'api'],

  // Sandboxing - containerized apps
  'SANDBOX-': ['webapp', 'api', 'mcp'],

  // Secret management - primarily for apps with secrets
  'SEC-': ['webapp', 'api', 'mcp'],

  // Semantic analysis - applies to all project types
  'SEM-': ['all'],
};

export interface ScanOptions {
  targetDir: string;
  autoFix?: boolean;
  /** Preview fixes without applying them */
  dryRun?: boolean;
  /** Check IDs to ignore (e.g., ['CRED-001', 'GIT-002']) */
  ignore?: string[];
  /** File/folder paths to ignore (e.g., ['.env', 'secrets/', 'test/']) */
  ignorePaths?: string[];
  /** Enable Layer 3 LLM analysis (requires ANTHROPIC_API_KEY in CLI mode) */
  deep?: boolean;
  /** Progress callback for long-running operations */
  onProgress?: (message: string) => void;
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

// OpenClaw skill security patterns
const SKILL_REMOTE_FETCH_PATTERNS: RegExp[] = [
  /curl\s+(-[a-zA-Z]+\s+)*https?:\/\//gi,
  /wget\s+(-[a-zA-Z]+\s+)*https?:\/\//gi,
  /fetch\s*\(\s*['"`]https?:\/\//gi,
  /\|\s*(ba)?sh/gi,  // pipe to shell
  /\|\s*sudo/gi,     // pipe to sudo
];

const SKILL_CREDENTIAL_ACCESS_PATTERNS: RegExp[] = [
  /~\/\.ssh/gi,
  /~\/\.aws/gi,
  /~\/\.config\/solana/gi,
  /~\/\.config\/gcloud/gi,
  /~\/\.kube/gi,
  /~\/\.gnupg/gi,
  /keychain/gi,
  /wallet.*\.json/gi,
  /seed.*phrase/gi,
  /private.*key/gi,
  /\.env/gi,
  /credentials\.json/gi,
];

const SKILL_EXFILTRATION_PATTERNS: RegExp[] = [
  /webhook\.site/gi,
  /requestbin/gi,
  /ngrok\.io/gi,
  /curl\s+[^\n]*?-d\s/gi,      // Non-greedy with newline boundary
  /curl\s+[^\n]*?--data/gi,
  /curl\s+[^\n]*?-X\s*POST/gi,
  /fetch\s*\([^)]*method:\s*['"]POST/gi,
];

const SKILL_REVERSE_SHELL_PATTERNS: RegExp[] = [
  /nc\s+(-[a-zA-Z]+\s+)*.*-e/gi,
  /bash\s+-i\s+/gi,
  /\/dev\/tcp\//gi,
  /\/dev\/udp\//gi,
  /python.*socket.*connect/gi,
  /perl.*socket.*connect/gi,
];

const SKILL_CLICKFIX_PATTERNS: RegExp[] = [
  /copy\s+(and\s+)?paste\s+(this\s+)?(into|in)\s+(your\s+)?terminal/gi,
  /run\s+this\s+command/gi,
  /execute\s+(the\s+following|this)/gi,
  /curl.*\|\s*(ba)?sh/gi,
  /wget.*\|\s*(ba)?sh/gi,
];

const HEARTBEAT_DANGEROUS_CAPS: string[] = [
  'shell:*',
  'shell:bash',
  'shell:sh',
  'filesystem:*',
  'filesystem:~/*',
  'filesystem:/',
  'network:*',
];

// ClawHavoc campaign IOCs (Koi Security research, Jan 2026)
const CLAWHAVOC_C2_IPS = ['91.92.242.30'];
const CLAWHAVOC_MALICIOUS_FILES = [
  'openclaw-agent.exe', 'openclaw-agent.zip', 'openclawcli.zip',
  'agent-setup.exe', 'openclaw-installer.dmg',
];
const CLAWHAVOC_CLICKFIX_PATTERNS: RegExp[] = [
  /download.*paste.*terminal/i,
  /copy.*(?:command|script).*terminal/i,
  /right[- ]click.*open/i,
  /run.*\.exe/i,
];
const CLAWHAVOC_ARCHIVE_PASSWORD = /password\s*[:=]\s*["']?(openclaw|claw|agent|setup)["']?/i;

const PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)/gi,
  /disregard\s+(all\s+)?(previous|prior)/gi,
  /system:\s/gi,
  /<\|.*\|>/gi,  // special tokens
  /\[INST\]/gi,
  /\[\/INST\]/gi,
  /<<SYS>>/gi,
  /Human:/gi,
  /Assistant:/gi,
];

// Severity weights for score calculation
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB max file size to prevent memory exhaustion
const MAX_LINE_LENGTH = 10000; // 10KB max line length for regex safety

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
    'openclaw.json',
    'moltbot.json',
  ];

  /**
   * Validate that a file path is within the target directory (no path traversal)
   */
  private isPathWithinDirectory(filePath: string, directory: string): boolean {
    const normalizedFile = path.resolve(filePath);
    const normalizedDir = path.resolve(directory);
    return normalizedFile.startsWith(normalizedDir + path.sep) || normalizedFile === normalizedDir;
  }

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

    // Detect platform and project type
    const platform = await this.detectPlatform(targetDir);
    const projectType = await this.detectProjectType(targetDir);

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

    // OpenClaw skill checks
    const skillFindings = await this.checkOpenclawSkills(targetDir, shouldFix);
    findings.push(...skillFindings);

    // OpenClaw heartbeat checks
    const heartbeatFindings = await this.checkOpenclawHeartbeat(targetDir, shouldFix);
    findings.push(...heartbeatFindings);

    // OpenClaw gateway checks
    const gatewayFindings = await this.checkOpenclawGateway(targetDir, shouldFix);
    findings.push(...gatewayFindings);

    // OpenClaw config checks
    const configFindings = await this.checkOpenclawConfig(targetDir, shouldFix);
    findings.push(...configFindings);

    // OpenClaw supply chain checks
    const supplyFindings = await this.checkOpenclawSupplyChain(targetDir, shouldFix);
    findings.push(...supplyFindings);

    // OpenClaw CVE-specific checks
    const cveFindings = await this.checkOpenclawCVE(targetDir, shouldFix);
    findings.push(...cveFindings);

    // Layer 2: Structural analysis (always on)
    let layer2Count = 0;
    let layer3Count = 0;
    let llmCost: number | undefined;
    let cachedResults: number | undefined;
    try {
      const structural = new StructuralAnalyzer();
      const structuralFindings = await structural.analyze(targetDir);
      const converted = toSecurityFindings(structuralFindings);
      findings.push(...converted);
      layer2Count = converted.length;
    } catch {
      // Structural analysis failure is non-fatal
    }

    // Layer 3: LLM analysis (only with --deep + API key in CLI mode)
    if (options.deep && process.env.ANTHROPIC_API_KEY) {
      try {
        const structural = new StructuralAnalyzer();
        const files = await structural.discoverFiles(targetDir);
        const llm = new LLMAnalyzer({
          apiKey: process.env.ANTHROPIC_API_KEY,
          onProgress: options.onProgress,
        });
        const llmResult = await llm.analyze(files);
        const converted = toSecurityFindings(llmResult.findings);
        findings.push(...converted);
        layer3Count = converted.length;
        llmCost = llmResult.cost;
        cachedResults = llmResult.cachedResults;
      } catch {
        // LLM analysis failure is non-fatal — fall back to Layer 2 only
      }
    }

    // Filter findings to only show real, actionable issues:
    // 1. Only failed checks (passed: false)
    // 2. Only checks with a file path (concrete findings, not generic advice)
    // 3. Filter out ignored checks
    let filteredFindings = findings.filter((f) => {
      // Keep fixed findings (so users can see what was fixed)
      // Otherwise, only show failed checks
      if (!f.fixed && f.passed) return false;

      // Only show concrete findings (has a file path)
      if (!f.file) return false;

      // Filter out ignored checks
      if (ignoredChecks.has(f.checkId.toUpperCase())) return false;

      return true;
    });

    // Calculate score (only on applicable, non-ignored findings)
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
      projectType,
      findings: filteredFindings,
      allFindings: findings, // Include unfiltered findings for benchmark evaluation
      score,
      maxScore,
      backupPath,
      dryRun: dryRun && autoFix ? true : undefined,
      atomicFix,
      ignored: ignoredChecks.size > 0 ? Array.from(ignoredChecks) : undefined,
      semanticAnalysis: (layer2Count > 0 || layer3Count > 0) ? {
        layer2Findings: layer2Count,
        layer3Findings: layer3Count,
        llmCost,
        cachedResults,
      } : undefined,
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

    // OpenClaw detection
    try {
      await fs.access(path.join(targetDir, '.openclaw'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.moltbot'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.clawdbot'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    // Check for openclaw.json
    try {
      await fs.access(path.join(targetDir, 'openclaw.json'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    // Check for SKILL.md files (OpenClaw skill project)
    try {
      const files = await fs.readdir(targetDir);
      if (files.some(f => f === 'SKILL.md' || f.endsWith('.skill.md'))) {
        if (!platforms.includes('openclaw')) {
          platforms.push('openclaw');
        }
      }
    } catch {}

    if (platforms.length === 0) {
      return 'generic';
    }

    return platforms.join('+');
  }

  /**
   * Detect the project type based on package.json and project structure
   */
  private async detectProjectType(targetDir: string): Promise<ProjectType> {
    // Check for OpenClaw project indicators (check first as it's more specific)
    const openclawIndicators = ['.openclaw', '.moltbot', '.clawdbot', 'SKILL.md', 'openclaw.json'];
    for (const indicator of openclawIndicators) {
      try {
        await fs.access(path.join(targetDir, indicator));
        return 'openclaw';
      } catch {}
    }

    // Check for *.skill.md files (OpenClaw skill project)
    try {
      const files = await fs.readdir(targetDir);
      if (files.some(f => f.endsWith('.skill.md'))) {
        return 'openclaw';
      }
    } catch {}

    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);

      // Check if it's a CLI tool (has bin field)
      if (pkg.bin) {
        return 'cli';
      }

      // Check dependencies for framework detection
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      // Check for MCP server
      if (
        allDeps['@modelcontextprotocol/sdk'] ||
        allDeps['mcp'] ||
        pkg.name?.includes('mcp')
      ) {
        return 'mcp';
      }

      // Check for web frameworks
      if (
        allDeps['react'] ||
        allDeps['vue'] ||
        allDeps['svelte'] ||
        allDeps['@angular/core'] ||
        allDeps['next'] ||
        allDeps['nuxt']
      ) {
        return 'webapp';
      }

      // Check for API frameworks
      if (
        allDeps['express'] ||
        allDeps['fastify'] ||
        allDeps['koa'] ||
        allDeps['hapi'] ||
        allDeps['@hapi/hapi'] ||
        allDeps['restify']
      ) {
        return 'api';
      }

      // Default to library if it has main/exports but no clear type
      if (pkg.main || pkg.exports || pkg.module) {
        return 'library';
      }
    } catch {
      // No package.json or invalid JSON
    }

    // Check for Python projects
    try {
      const setupPath = path.join(targetDir, 'setup.py');
      await fs.access(setupPath);
      return 'library';
    } catch {}

    try {
      const pyprojectPath = path.join(targetDir, 'pyproject.toml');
      const content = await fs.readFile(pyprojectPath, 'utf-8');
      if (content.includes('fastapi') || content.includes('flask') || content.includes('django')) {
        return 'api';
      }
      return 'library';
    } catch {}

    // Default to library for generic projects
    return 'library';
  }

  /**
   * Check if a finding applies to the given project type
   */
  private findingAppliesTo(finding: SecurityFinding, projectType: ProjectType): boolean {
    // Find the matching rule based on check ID prefix
    for (const [prefix, types] of Object.entries(CHECK_PROJECT_TYPES)) {
      if (finding.checkId.startsWith(prefix)) {
        // Check if 'all' is in the types array
        if (types.includes('all')) {
          return true;
        }
        return types.includes(projectType);
      }
    }
    // Default: applies to all if no rule found
    return true;
  }

  private async checkCredentialExposure(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const envVarsToAdd: Set<string> = new Set();

    // Credential patterns with their env var names (stricter to avoid false positives)
    const credentialPatterns = [
      { name: 'Anthropic API Key', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g, envVar: 'ANTHROPIC_API_KEY' },
      { name: 'OpenAI API Key', pattern: /sk-proj-[a-zA-Z0-9]{20,}/g, envVar: 'OPENAI_API_KEY' },
      { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48,}/g, envVar: 'OPENAI_API_KEY' },
      { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, envVar: 'AWS_ACCESS_KEY_ID' },
      { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/g, envVar: 'GITHUB_TOKEN' },
      { name: 'GitHub Token', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, envVar: 'GITHUB_TOKEN' },
      { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, envVar: 'GOOGLE_API_KEY' },
      { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, envVar: 'STRIPE_SECRET_KEY' },
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
      'CLAUDE.md',
    ];

    for (const filename of filesToCheck) {
      const filePath = path.join(targetDir, filename);
      try {
        let content = await fs.readFile(filePath, 'utf-8');
        const lines = content.split('\n');
        let fileModified = false;
        const keysFoundInFile: Array<{ name: string; line: number }> = [];

        for (const { name, pattern, envVar } of credentialPatterns) {
          // Check each line for credentials
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            if (pattern.test(lines[i]) && !lines[i].includes('${' + envVar + '}')) {
              keysFoundInFile.push({ name, line: i + 1 });

              if (autoFix) {
                pattern.lastIndex = 0;
                lines[i] = lines[i].replace(pattern, '${' + envVar + '}');
                fileModified = true;
                envVarsToAdd.add(envVar);
              }
            }
          }
        }

        // Report one finding per file with exposed credentials
        if (keysFoundInFile.length > 0) {
          const keyNames = [...new Set(keysFoundInFile.map((k) => k.name))];
          const firstLine = keysFoundInFile[0].line;

          if (fileModified) {
            content = lines.join('\n');
            await fs.writeFile(filePath, content);
          }

          findings.push({
            checkId: 'CRED-001',
            name: 'Exposed Credential',
            description: `${keyNames.join(', ')} found in plaintext`,
            category: 'credentials',
            severity: 'critical',
            passed: fileModified, // Fixed if we replaced it
            message: keyNames.join(', '),
            file: filename,
            line: firstLine,
            fixable: true,
            fixed: fileModified,
            fix: `Run \`hackmyagent secure --fix\` to replace the hardcoded credential with a \${ENV_VAR} reference, then store the actual value in your .env file`,
          });
        }
      } catch {
        // File doesn't exist, skip
      }
    }

    // Create .env.example if we fixed any credentials
    if (autoFix && envVarsToAdd.size > 0) {
      const envExamplePath = path.join(targetDir, '.env.example');
      let envExampleContent = '# Environment variables\n\n';
      for (const envVar of envVarsToAdd) {
        envExampleContent += `${envVar}=\n`;
      }
      await fs.writeFile(envExamplePath, envExampleContent);
    }

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
      const lines = content.split('\n');
      let credentialLine: number | undefined;
      let credentialType: string | undefined;

      // Check for credentials in CLAUDE.md
      for (const { name, pattern } of CREDENTIAL_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
          if (pattern.test(lines[i])) {
            credentialLine = i + 1;
            credentialType = name;
            break;
          }
        }
        if (credentialLine) break;
      }

      // Only report if credentials found
      if (credentialLine) {
        findings.push({
          checkId: 'CLAUDE-001',
          name: 'Credential in CLAUDE.md',
          description: `${credentialType} found in CLAUDE.md`,
          category: 'claude-code',
          severity: 'critical',
          passed: false,
          message: 'Remove credentials from CLAUDE.md',
          file: 'CLAUDE.md',
          line: credentialLine,
          fixable: false,
          fix: 'Manually move the credential to a .env file and reference it as ${ENV_VAR}. CLAUDE.md may be committed to git and exposed publicly',
        });
      }
    } catch {
      // CLAUDE.md doesn't exist, that's fine - no finding needed
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

      // Only report if there's an issue
      if (hasRootAccess) {
        findings.push({
          checkId: 'MCP-001',
          name: 'MCP Root Filesystem Access',
          description: 'Server has access to / or ~ directory',
          category: 'mcp',
          severity: 'high',
          passed: mcp001Fixed,
          message: 'Restrict filesystem access to specific directories',
          file: 'mcp.json',
          fixable: true,
          fixed: mcp001Fixed,
          fix: 'Run `hackmyagent secure --fix` to restrict filesystem access from / or ~ to project-relative paths (./data or ./)',
        });
      }

      if (hasUnrestrictedShell) {
        findings.push({
          checkId: 'MCP-002',
          name: 'Unrestricted Shell Server',
          description: 'Shell server has no command restrictions',
          category: 'mcp',
          severity: 'critical',
          passed: false,
          message: 'Add allowedCommands to restrict shell access',
          file: 'mcp.json',
          fixable: false,
          fix: 'Manually add an "allowedCommands" array to your shell server config in mcp.json to whitelist specific commands (e.g., ["ls", "cat", "grep"])',
        });
      }
    } catch {
      // mcp.json doesn't exist - no findings needed
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

    // Only report if .gitignore is missing
    if (!gitignoreExists || git001Fixed) {
      findings.push({
        checkId: 'GIT-001',
        name: 'Missing .gitignore',
        description: 'No .gitignore file to prevent accidental commits',
        category: 'git',
        severity: 'medium',
        passed: git001Fixed,
        message: 'Create .gitignore to protect sensitive files',
        file: '.gitignore',
        fixable: true,
        fixed: git001Fixed,
        fix: 'Run `hackmyagent secure --fix` to create a .gitignore with security patterns (.env, secrets.json, *.pem, *.key) to prevent accidental commits',
      });
    }

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

    // Only report if patterns are missing
    if (missingPatterns.length > 0) {
      findings.push({
        checkId: 'GIT-002',
        name: 'Incomplete .gitignore',
        description: `Missing: ${missingPatterns.join(', ')}`,
        category: 'git',
        severity: 'high',
        passed: git002Fixed,
        message: `Add patterns: ${missingPatterns.join(', ')}`,
        file: '.gitignore',
        fixable: true,
        fixed: git002Fixed,
        fix: `Run \`hackmyagent secure --fix\` to add ${missingPatterns.join(', ')} to .gitignore so sensitive files won't be accidentally committed`,
      });
    }

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

    // Only report if .env is at risk
    if (envAtRisk) {
      findings.push({
        checkId: 'GIT-003',
        name: '.env Not Ignored',
        description: '.env exists but not in .gitignore - secrets may be committed',
        category: 'git',
        severity: 'critical',
        passed: git003Fixed,
        message: 'Add .env to .gitignore',
        file: '.env',
        fixable: true,
        fixed: git003Fixed,
        fix: 'Run `hackmyagent secure --fix` to add .env to .gitignore so your environment variables won\'t be accidentally committed',
      });
    }

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

    // Only report if bound to 0.0.0.0
    if (boundToAllInterfaces) {
      findings.push({
        checkId: 'NET-001',
        name: 'Server Bound to All Interfaces',
        description: 'Server bound to 0.0.0.0 - accessible from any network',
        category: 'network',
        severity: 'critical',
        passed: net001Fixed,
        message: 'Change 0.0.0.0 to 127.0.0.1',
        file: 'mcp.json',
        fixable: true,
        fixed: net001Fixed,
        fix: 'Run `hackmyagent secure --fix` to change 0.0.0.0 to 127.0.0.1 so the server only accepts local connections instead of being exposed to the network',
      });
    }

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

    // Only report if insecure remote found
    if (hasInsecureRemote) {
      findings.push({
        checkId: 'NET-002',
        name: 'Remote MCP Without TLS',
        description: 'Remote server using HTTP instead of HTTPS',
        category: 'network',
        severity: 'high',
        passed: false,
        message: 'Change http:// to https://',
        file: 'mcp.json',
        fixable: false,
        fix: 'Manually change http:// to https:// in mcp.json to encrypt traffic and prevent man-in-the-middle attacks',
      });
    }

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

    // Only report if hardcoded secrets found
    if (hasHardcodedSecrets) {
      findings.push({
        checkId: 'MCP-003',
        name: 'Hardcoded Secrets in MCP',
        description: 'Secrets found in MCP env vars',
        category: 'mcp',
        severity: 'critical',
        passed: mcp003Fixed,
        message: 'Use ${ENV_VAR} references instead',
        file: 'mcp.json',
        fixable: true,
        fixed: mcp003Fixed,
        fix: 'Run `hackmyagent secure --fix` to replace hardcoded API keys with ${ENV_VAR} references, then store actual values in .env file',
      });
    }

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

    // Only report if default credentials found
    if (hasDefaultCreds) {
      findings.push({
        checkId: 'MCP-004',
        name: 'Default Credentials',
        description: 'MCP server using default password',
        category: 'mcp',
        severity: 'critical',
        passed: false,
        message: 'Change to strong unique password',
        file: 'mcp.json',
        fixable: false,
        fix: 'Manually change the default password in mcp.json to a strong, unique password (use `openssl rand -base64 24` to generate one)',
      });
    }

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

    // Only report if wildcard tools found
    if (hasWildcardTools) {
      findings.push({
        checkId: 'MCP-005',
        name: 'Wildcard Tool Access',
        description: 'Server allows all tools (*)',
        category: 'mcp',
        severity: 'high',
        passed: false,
        message: 'Restrict to specific tools needed',
        file: 'mcp.json',
        fixable: false,
        fix: 'Manually replace "*" with a list of specific tool names you need (e.g., ["read_file", "list_directory"]) to limit what the AI can access',
      });
    }

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

    // Only report if overly permissive
    if (hasOverlyPermissive) {
      findings.push({
        checkId: 'CLAUDE-002',
        name: 'Overly Permissive Permissions',
        description: 'Settings allow unrestricted tool access',
        category: 'claude-code',
        severity: 'high',
        passed: false,
        message: 'Scope permissions to specific paths',
        file: '.claude/settings.json',
        fixable: false,
        fix: 'Manually replace wildcards like Bash(*) or Read(*) with specific paths (e.g., Bash(npm test) or Read(/src/**)) to limit AI access',
      });
    }

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

    // Only report if dangerous Bash patterns found
    if (hasDangerousBash) {
      findings.push({
        checkId: 'CLAUDE-003',
        name: 'Dangerous Bash Permissions',
        description: 'Allows destructive shell commands',
        category: 'claude-code',
        severity: 'critical',
        passed: false,
        message: 'Remove rm -rf, sudo, etc.',
        file: '.claude/settings.json',
        fixable: false,
        fix: 'Manually remove dangerous commands (rm -rf, sudo, chmod 777, etc.) from the allow list in .claude/settings.json to prevent accidental destructive operations',
      });
    }

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

    // All findings passed in are concrete issues (already filtered)
    for (const finding of findings) {
      const weight = SEVERITY_WEIGHTS[finding.severity];

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
      throw new Error('No backup found. Run hackmyagent harden --fix <dir> first to create a backup.');
    }

    // Find the most recent backup
    const backups = await fs.readdir(backupBaseDir);
    const sortedBackups = backups
      .filter((b) => !b.startsWith('.'))
      .sort()
      .reverse();

    if (sortedBackups.length === 0) {
      throw new Error('No backup found. Run hackmyagent harden --fix <dir> first to create a backup.');
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
      throw new Error('Backup manifest is corrupted. Delete ~/.hackmyagent/backups/ and re-run hackmyagent harden --fix.');
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

  /**
   * Recursively find SKILL.md and *.skill.md files
   * Skips node_modules and limits depth to 5
   */
  private async findSkillFiles(dir: string, depth: number = 0, rootDir?: string): Promise<string[]> {
    if (depth > 5) {
      return [];
    }

    const baseDir = rootDir || dir;
    const skillFiles: string[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        // Skip symlinks to prevent path traversal
        if (entry.isSymbolicLink()) {
          continue;
        }

        const fullPath = path.join(dir, entry.name);

        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, baseDir)) {
          continue;
        }

        if (entry.isDirectory()) {
          // Skip node_modules and hidden directories (except .openclaw, .moltbot, .clawdbot)
          if (entry.name === 'node_modules') continue;
          if (entry.name.startsWith('.') &&
              !['openclaw', 'moltbot', 'clawdbot'].includes(entry.name.slice(1))) {
            continue;
          }

          const subFiles = await this.findSkillFiles(fullPath, depth + 1, baseDir);
          skillFiles.push(...subFiles);
        } else if (entry.isFile()) {
          // Match SKILL.md or *.skill.md
          if (entry.name === 'SKILL.md' || entry.name.endsWith('.skill.md')) {
            skillFiles.push(fullPath);
          }
        }
      }
    } catch {
      // Directory not accessible, skip
    }

    return skillFiles;
  }

  /**
   * OpenClaw skill security checks (SKILL-001 to SKILL-006)
   */
  private async checkOpenclawSkills(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const skillFiles = await this.findSkillFiles(targetDir);

    for (const skillFile of skillFiles) {
      const relativePath = path.relative(targetDir, skillFile);

      let content: string;
      try {
        const stats = await fs.stat(skillFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(skillFile, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n').map(line =>
        line.length > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) : line
      );

      // SKILL-001: Unsigned Skill
      const hasSignature =
        content.includes('opena2a_signature:') ||
        content.includes('-----BEGIN SIGNATURE-----');

      findings.push({
        checkId: 'SKILL-001',
        name: 'Unsigned Skill',
        description: 'Skill file lacks cryptographic signature for authenticity verification',
        category: 'skill',
        severity: 'medium',
        passed: hasSignature,
        message: hasSignature
          ? 'Skill has cryptographic signature'
          : 'Skill is unsigned - cannot verify authenticity or integrity',
        file: relativePath,
        fixable: false,
        fix: 'Sign the skill using: openclaw sign skill.md --key ~/.openclaw/signing-key.pem',
      });

      // SKILL-002: Remote Fetch Pattern
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_REMOTE_FETCH_PATTERNS) {
          // Reset regex lastIndex for global patterns
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SKILL-002',
              name: 'Remote Fetch Pattern',
              description: 'Skill contains pattern that fetches and executes remote code',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `Remote fetch pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove curl|sh, wget|sh, and other remote code execution patterns',
            });
            break; // One finding per line
          }
        }
      }

      // SKILL-003: Heartbeat Installation
      const heartbeatPattern = /heartbeat|cron|schedule|every\s+\d+\s*(min|hour|sec)/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        heartbeatPattern.lastIndex = 0;
        if (heartbeatPattern.test(line)) {
          findings.push({
            checkId: 'SKILL-003',
            name: 'Heartbeat Installation',
            description: 'Skill attempts to install periodic/scheduled tasks',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `Heartbeat/scheduled task pattern detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Heartbeats should be configured separately with restricted permissions, not bundled in skills',
          });
        }
      }

      // SKILL-004: Filesystem Write Outside Sandbox
      const filesystemWildcardPattern = /filesystem:\s*\*|filesystem:\s*~\/\*|filesystem:\s*\//gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        filesystemWildcardPattern.lastIndex = 0;
        if (filesystemWildcardPattern.test(line)) {
          findings.push({
            checkId: 'SKILL-004',
            name: 'Filesystem Write Outside Sandbox',
            description: 'Skill requests broad filesystem access outside sandbox',
            category: 'skill',
            severity: 'critical',
            passed: false,
            message: `Broad filesystem access requested: "${line.trim()}"`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Restrict filesystem access to specific directories (e.g., filesystem:./data/*)',
          });
        }
      }

      // SKILL-005: Credential File Access
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_CREDENTIAL_ACCESS_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SKILL-005',
              name: 'Credential File Access',
              description: 'Skill attempts to access credential or sensitive configuration files',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `Credential file access pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Skills should never access credential files like ~/.ssh, ~/.aws, wallets, or .env files',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-006: Data Exfiltration Pattern
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_EXFILTRATION_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SKILL-006',
              name: 'Data Exfiltration Pattern',
              description: 'Skill contains patterns commonly used for data exfiltration',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `Data exfiltration pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove webhook.site, requestbin, ngrok, and suspicious POST patterns',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-007: ClickFix Social Engineering
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_CLICKFIX_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SKILL-007',
              name: 'ClickFix Social Engineering',
              description: 'Skill uses social engineering tactics to trick users into running commands',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `ClickFix social engineering pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove social engineering instructions that trick users into copying/pasting commands',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-008: Reverse Shell Pattern
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_REVERSE_SHELL_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SKILL-008',
              name: 'Reverse Shell Pattern',
              description: 'Skill contains patterns commonly used to establish reverse shells',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `Reverse shell pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove netcat, bash -i, /dev/tcp, and other reverse shell patterns',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-009: Typosquatting Name
      const popularSkills = [
        'filesystem',
        'github',
        'slack',
        'discord',
        'postgres',
        'sqlite',
        'fetch',
        'browser',
        'puppeteer',
        'playwright',
      ];
      const skillBasename = path.basename(skillFile, path.extname(skillFile)).toLowerCase();
      for (const popular of popularSkills) {
        if (skillBasename !== popular && this.levenshteinDistance(skillBasename, popular) <= 2) {
          findings.push({
            checkId: 'SKILL-009',
            name: 'Typosquatting Name',
            description: 'Skill name is suspiciously similar to a popular skill (potential typosquatting)',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `Skill name "${skillBasename}" is similar to popular skill "${popular}" (potential typosquatting)`,
            file: relativePath,
            fixable: false,
            fix: 'Rename the skill to avoid confusion with popular skills, or verify this is intentional',
          });
          break; // One typosquatting finding per skill file
        }
      }

      // SKILL-010: Env File Exfiltration
      const envFilePattern = /\.env|dotenv|process\.env|environ|getenv/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        envFilePattern.lastIndex = 0;
        if (envFilePattern.test(line)) {
          findings.push({
            checkId: 'SKILL-010',
            name: 'Env File Exfiltration',
            description: 'Skill attempts to access environment files or variables',
            category: 'skill',
            severity: 'critical',
            passed: false,
            message: `Environment file/variable access detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Skills should not access .env files or environment variables containing secrets',
          });
        }
      }

      // SKILL-011: Browser Data Access
      const browserDataPattern = /chrome|firefox|cookies|localStorage|sessionStorage|browser.*data|chromium|safari.*cookies/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        browserDataPattern.lastIndex = 0;
        if (browserDataPattern.test(line)) {
          findings.push({
            checkId: 'SKILL-011',
            name: 'Browser Data Access',
            description: 'Skill attempts to access browser data, cookies, or local storage',
            category: 'skill',
            severity: 'critical',
            passed: false,
            message: `Browser data access pattern detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Skills should not access browser data, cookies, localStorage, or sessionStorage',
          });
        }
      }

      // SKILL-012: Crypto Wallet Access
      const cryptoWalletPattern = /wallet|solana|phantom|metamask|ledger|seed\s*phrase|mnemonic|\.sol\b|\.eth\b|private\s*key/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        cryptoWalletPattern.lastIndex = 0;
        if (cryptoWalletPattern.test(line)) {
          findings.push({
            checkId: 'SKILL-012',
            name: 'Crypto Wallet Access',
            description: 'Skill attempts to access cryptocurrency wallets or seed phrases',
            category: 'skill',
            severity: 'critical',
            passed: false,
            message: `Crypto wallet access pattern detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Skills should never access cryptocurrency wallets, seed phrases, or private keys',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Recursively find HEARTBEAT.md and *.heartbeat.md files
   * Skips node_modules and limits depth to 5
   */
  private async findHeartbeatFiles(dir: string, depth: number = 0, rootDir?: string): Promise<string[]> {
    if (depth > 5) {
      return [];
    }

    const baseDir = rootDir || dir;
    const heartbeatFiles: string[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        // Skip symlinks to prevent path traversal
        if (entry.isSymbolicLink()) {
          continue;
        }

        const fullPath = path.join(dir, entry.name);

        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, baseDir)) {
          continue;
        }

        if (entry.isDirectory()) {
          // Skip node_modules and hidden directories (except .openclaw, .moltbot, .clawdbot)
          if (entry.name === 'node_modules') continue;
          if (entry.name.startsWith('.') &&
              !['openclaw', 'moltbot', 'clawdbot'].includes(entry.name.slice(1))) {
            continue;
          }

          const subFiles = await this.findHeartbeatFiles(fullPath, depth + 1, baseDir);
          heartbeatFiles.push(...subFiles);
        } else if (entry.isFile()) {
          // Match HEARTBEAT.md or *.heartbeat.md
          if (entry.name === 'HEARTBEAT.md' || entry.name.endsWith('.heartbeat.md')) {
            heartbeatFiles.push(fullPath);
          }
        }
      }
    } catch {
      // Directory not accessible, skip
    }

    return heartbeatFiles;
  }

  /**
   * OpenClaw heartbeat security checks (HEARTBEAT-001 to HEARTBEAT-006)
   */
  private async checkOpenclawHeartbeat(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const heartbeatFiles = await this.findHeartbeatFiles(targetDir);

    for (const heartbeatFile of heartbeatFiles) {
      const relativePath = path.relative(targetDir, heartbeatFile);

      let content: string;
      try {
        const stats = await fs.stat(heartbeatFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(heartbeatFile, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n').map(line =>
        line.length > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) : line
      );

      // HEARTBEAT-001: Unverified Heartbeat URL
      const urlPattern = /https?:\/\/[^\s]+/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        urlPattern.lastIndex = 0;
        const match = urlPattern.exec(line);
        if (match) {
          findings.push({
            checkId: 'HEARTBEAT-001',
            name: 'Unverified Heartbeat URL',
            description: 'Heartbeat contacts external URL without verification',
            category: 'heartbeat',
            severity: 'critical',
            passed: false,
            message: `External URL detected in heartbeat: "${match[0].substring(0, 60)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Verify the URL is from a trusted source and add hash pinning for integrity',
          });
        }
      }

      // HEARTBEAT-002: No Hash Pinning
      const hasHashPinning =
        content.includes('pinned_hash:') ||
        content.includes('sha256:') ||
        content.includes('hash:');

      findings.push({
        checkId: 'HEARTBEAT-002',
        name: 'No Hash Pinning',
        description: 'Heartbeat lacks hash pinning for content integrity verification',
        category: 'heartbeat',
        severity: 'high',
        passed: hasHashPinning,
        message: hasHashPinning
          ? 'Heartbeat has hash pinning for integrity verification'
          : 'Heartbeat lacks hash pinning - content integrity cannot be verified',
        file: relativePath,
        fixable: false,
        fix: 'Add pinned_hash: sha256:<hash> to verify heartbeat content integrity',
      });

      // HEARTBEAT-003: Unsigned Heartbeat
      const hasSignature =
        content.includes('opena2a_signature:') ||
        content.includes('signature:') ||
        content.includes('-----BEGIN SIGNATURE-----');

      findings.push({
        checkId: 'HEARTBEAT-003',
        name: 'Unsigned Heartbeat',
        description: 'Heartbeat file lacks cryptographic signature',
        category: 'heartbeat',
        severity: 'high',
        passed: hasSignature,
        message: hasSignature
          ? 'Heartbeat has cryptographic signature'
          : 'Heartbeat is unsigned - cannot verify authenticity or integrity',
        file: relativePath,
        fixable: false,
        fix: 'Sign the heartbeat using: openclaw sign heartbeat.md --key ~/.openclaw/signing-key.pem',
      });

      // HEARTBEAT-004: Dangerous Capabilities
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].toLowerCase();
        for (const cap of HEARTBEAT_DANGEROUS_CAPS) {
          if (line.includes(cap.toLowerCase())) {
            findings.push({
              checkId: 'HEARTBEAT-004',
              name: 'Dangerous Capabilities',
              description: 'Heartbeat requests dangerous capabilities',
              category: 'heartbeat',
              severity: 'critical',
              passed: false,
              message: `Dangerous capability "${cap}" detected in heartbeat`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Heartbeats should use minimal capabilities - avoid shell:*, filesystem:*, network:*',
            });
          }
        }
      }

      // HEARTBEAT-005: Excessive Frequency
      // Match both "every: 30s" and "Every 30 minutes:" formats
      const frequencyPattern = /every[:\s]+(\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hours?)/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        frequencyPattern.lastIndex = 0;
        const match = frequencyPattern.exec(line);
        if (match) {
          const value = parseInt(match[1], 10);
          const unit = match[2].toLowerCase();

          // Calculate interval in minutes
          let intervalMinutes = value;
          if (unit.startsWith('s')) {
            intervalMinutes = value / 60;
          } else if (unit.startsWith('h')) {
            intervalMinutes = value * 60;
          }

          if (intervalMinutes < 5) {
            findings.push({
              checkId: 'HEARTBEAT-005',
              name: 'Excessive Frequency',
              description: 'Heartbeat runs too frequently (< 5 minutes)',
              category: 'heartbeat',
              severity: 'medium',
              passed: false,
              message: `Heartbeat interval of ${value}${unit} is less than 5 minutes`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Increase heartbeat interval to at least 5 minutes to prevent resource exhaustion',
            });
          }
        }
      }

      // HEARTBEAT-006: No Active Hours Limit
      const hasActiveHours =
        /activeHours:/i.test(content) ||
        /schedule:/i.test(content) ||
        /time_window:/i.test(content) ||
        /run_between:/i.test(content);

      findings.push({
        checkId: 'HEARTBEAT-006',
        name: 'No Active Hours Limit',
        description: 'Heartbeat lacks time-of-day restrictions',
        category: 'heartbeat',
        severity: 'medium',
        passed: hasActiveHours,
        message: hasActiveHours
          ? 'Heartbeat has active hours restriction'
          : 'Heartbeat can run 24/7 without time restrictions',
        file: relativePath,
        fixable: false,
        fix: 'Add activeHours: or schedule: to limit when the heartbeat can run',
      });
    }

    return findings;
  }

  /**
   * Find OpenClaw gateway configuration files
   */
  private async findGatewayConfigFiles(dir: string): Promise<string[]> {
    const configFiles: string[] = [];
    const candidates = [
      'openclaw.json',
      '.openclaw/config.json',
      'moltbot.json',
      '.moltbot/config.json',
    ];

    for (const candidate of candidates) {
      const fullPath = path.join(dir, candidate);
      try {
        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, dir)) {
          continue;
        }
        // Check if it's a symlink
        const stats = await fs.lstat(fullPath);
        if (stats.isSymbolicLink()) {
          continue; // Skip symlinks to prevent path traversal
        }
        await fs.access(fullPath);
        configFiles.push(fullPath);
      } catch {
        // File doesn't exist
      }
    }

    return configFiles;
  }

  /**
   * OpenClaw gateway security checks (GATEWAY-001 to GATEWAY-006)
   */
  private async checkOpenclawGateway(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const configFiles = await this.findGatewayConfigFiles(targetDir);

    for (const configFile of configFiles) {
      const relativePath = path.relative(targetDir, configFile);

      let content: string;
      let config: Record<string, unknown>;
      try {
        const stats = await fs.stat(configFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(configFile, 'utf-8');
        config = JSON.parse(content);
      } catch {
        continue;
      }

      // Track what fixes we apply
      let configModified = false;
      const fixesApplied: string[] = [];

      // GATEWAY-001: Bound to 0.0.0.0
      const gateway = config.gateway as Record<string, unknown> | undefined;
      const boundToAllInterfaces = gateway && gateway.host === '0.0.0.0';
      let gateway001Fixed = false;

      if (boundToAllInterfaces && autoFix) {
        // Fix: Change 0.0.0.0 to 127.0.0.1
        (config.gateway as Record<string, unknown>).host = '127.0.0.1';
        gateway001Fixed = true;
        configModified = true;
        fixesApplied.push('Changed gateway.host from 0.0.0.0 to 127.0.0.1 (local-only access)');
      }

      if (boundToAllInterfaces) {
        findings.push({
          checkId: 'GATEWAY-001',
          name: 'Bound to 0.0.0.0',
          description: 'Gateway is bound to all interfaces (0.0.0.0)',
          category: 'gateway',
          severity: 'critical',
          passed: gateway001Fixed,
          message: gateway001Fixed
            ? 'Fixed: Gateway now bound to 127.0.0.1 (local-only)'
            : 'Gateway host is 0.0.0.0 - accessible from any network interface',
          file: relativePath,
          fixable: true,
          fixed: gateway001Fixed,
          fixMessage: gateway001Fixed ? 'Changed gateway.host from 0.0.0.0 to 127.0.0.1' : undefined,
          fix: 'Run `hackmyagent secure-openclaw --fix` to bind gateway to 127.0.0.1 for local-only access',
        });
      }

      // GATEWAY-002: Missing WebSocket Origin Validation (not auto-fixable - requires user to specify allowed origins)
      const security = config.security as Record<string, unknown> | undefined;
      const hasWebSocketOrigins = security && security.websocketOrigins;
      findings.push({
        checkId: 'GATEWAY-002',
        name: 'Missing WebSocket Origin Validation',
        description: 'Gateway lacks WebSocket origin validation (GHSA-g8p2)',
        category: 'gateway',
        severity: 'critical',
        passed: Boolean(hasWebSocketOrigins),
        message: hasWebSocketOrigins
          ? 'WebSocket origin validation is configured'
          : 'Missing security.websocketOrigins - vulnerable to GHSA-g8p2 cross-origin attacks',
        file: relativePath,
        fixable: false,
        fix: 'Manually add security.websocketOrigins array with your allowed origins (e.g., ["http://localhost:3000"])',
      });

      // GATEWAY-003: Token Exposed in Config
      const gatewayAuth = gateway?.auth as Record<string, unknown> | undefined;
      const hasPlaintextTokenInAuth = gatewayAuth && typeof gatewayAuth.token === 'string' && gatewayAuth.token.length > 0;
      const hasPlaintextTokenAtRoot = typeof config.token === 'string' && (config.token as string).length > 0;
      const hasPlaintextToken = hasPlaintextTokenInAuth || hasPlaintextTokenAtRoot;
      let gateway003Fixed = false;

      if (hasPlaintextToken && autoFix) {
        // Fix: Replace plaintext token with environment variable reference
        if (hasPlaintextTokenInAuth && gatewayAuth) {
          gatewayAuth.token = '${OPENCLAW_AUTH_TOKEN}';
          gateway003Fixed = true;
          configModified = true;
          fixesApplied.push('Replaced gateway.auth.token with ${OPENCLAW_AUTH_TOKEN} env var reference');
        }
        if (hasPlaintextTokenAtRoot) {
          config.token = '${OPENCLAW_AUTH_TOKEN}';
          gateway003Fixed = true;
          configModified = true;
          fixesApplied.push('Replaced token with ${OPENCLAW_AUTH_TOKEN} env var reference');
        }
      }

      if (hasPlaintextToken) {
        findings.push({
          checkId: 'GATEWAY-003',
          name: 'Token Exposed in Config',
          description: 'Plaintext authentication token stored in configuration file',
          category: 'gateway',
          severity: 'critical',
          passed: gateway003Fixed,
          message: gateway003Fixed
            ? 'Fixed: Token replaced with ${OPENCLAW_AUTH_TOKEN} - set this env var with your actual token'
            : 'Plaintext token found in configuration - use environment variables instead',
          file: relativePath,
          fixable: true,
          fixed: gateway003Fixed,
          fixMessage: gateway003Fixed ? 'Replaced plaintext token with ${OPENCLAW_AUTH_TOKEN} env var reference. Set OPENCLAW_AUTH_TOKEN in your environment.' : undefined,
          fix: 'Run `hackmyagent secure-openclaw --fix` to replace plaintext token with ${OPENCLAW_AUTH_TOKEN} env var reference',
        });
      }

      // GATEWAY-004: Approval Confirmations Disabled
      const exec = config.exec as Record<string, unknown> | undefined;
      const approvals = exec?.approvals as Record<string, unknown> | undefined;
      const configApprovals = config.approvals as Record<string, unknown> | undefined;
      const approvalsDisabled =
        approvals?.set === 'off' ||
        approvals?.enabled === false ||
        configApprovals?.enabled === false;
      let gateway004Fixed = false;

      if (approvalsDisabled && autoFix) {
        // Fix: Enable approvals
        if (approvals?.set === 'off') {
          approvals.set = 'on';
          gateway004Fixed = true;
          configModified = true;
          fixesApplied.push('Changed exec.approvals.set from "off" to "on"');
        }
        if (approvals?.enabled === false) {
          approvals.enabled = true;
          gateway004Fixed = true;
          configModified = true;
          fixesApplied.push('Changed exec.approvals.enabled to true');
        }
        if (configApprovals?.enabled === false) {
          configApprovals.enabled = true;
          gateway004Fixed = true;
          configModified = true;
          fixesApplied.push('Changed approvals.enabled to true');
        }
      }

      if (approvalsDisabled) {
        findings.push({
          checkId: 'GATEWAY-004',
          name: 'Approval Confirmations Disabled',
          description: 'Execution approval confirmations are disabled',
          category: 'gateway',
          severity: 'critical',
          passed: gateway004Fixed,
          message: gateway004Fixed
            ? 'Fixed: Approval confirmations are now enabled - commands will require user confirmation'
            : 'Approval confirmations disabled - commands execute without user confirmation',
          file: relativePath,
          fixable: true,
          fixed: gateway004Fixed,
          fixMessage: gateway004Fixed ? 'Enabled approval confirmations for command execution' : undefined,
          fix: 'Run `hackmyagent secure-openclaw --fix` to enable approval confirmations for safer command execution',
        });
      }

      // GATEWAY-005: Sandbox Disabled
      const sandbox = config.sandbox as Record<string, unknown> | undefined;
      const sandboxDisabled = sandbox && sandbox.enabled === false;
      let gateway005Fixed = false;

      if (sandboxDisabled && autoFix) {
        // Fix: Enable sandbox
        sandbox.enabled = true;
        gateway005Fixed = true;
        configModified = true;
        fixesApplied.push('Changed sandbox.enabled to true');
      }

      if (sandboxDisabled) {
        findings.push({
          checkId: 'GATEWAY-005',
          name: 'Sandbox Disabled',
          description: 'Sandbox execution environment is disabled',
          category: 'gateway',
          severity: 'critical',
          passed: gateway005Fixed,
          message: gateway005Fixed
            ? 'Fixed: Sandbox is now enabled - code executes in isolated environment'
            : 'Sandbox is disabled - code executes with full system access',
          file: relativePath,
          fixable: true,
          fixed: gateway005Fixed,
          fixMessage: gateway005Fixed ? 'Enabled sandbox mode for isolated code execution' : undefined,
          fix: 'Run `hackmyagent secure-openclaw --fix` to enable sandbox mode for safer code execution',
        });
      }

      // GATEWAY-006: Container Escape Risk (not auto-fixable - requires manual review of mount points)
      const docker = config.docker as Record<string, unknown> | undefined;
      const isPrivileged = docker?.privileged === true;
      const mounts = docker?.mounts as string[] | undefined;
      const hasDangerousMounts = mounts?.some(
        (mount: string) =>
          mount.includes('/var/run/docker.sock') ||
          mount.includes('/etc/passwd') ||
          mount.includes('/etc/shadow') ||
          mount.startsWith('/:/') ||
          mount.includes(':/host')
      );

      if (isPrivileged || hasDangerousMounts) {
        const issues: string[] = [];
        if (isPrivileged) issues.push('privileged mode');
        if (hasDangerousMounts) issues.push('sensitive host mounts');
        findings.push({
          checkId: 'GATEWAY-006',
          name: 'Container Escape Risk',
          description: 'Docker configuration allows container escape',
          category: 'gateway',
          severity: 'critical',
          passed: false,
          message: `Container escape risk: ${issues.join(', ')}`,
          file: relativePath,
          fixable: false,
          fix: 'Manually disable privileged mode and remove sensitive host mounts - requires careful review',
        });
      }

      // GATEWAY-007: Open DM Policy with Wildcard
      const channels = config.channels as Record<string, Record<string, unknown>> | undefined;
      const dm = config.dm as Record<string, unknown> | undefined;
      let hasOpenDmWildcard = false;

      if (channels) {
        for (const [, channelConfig] of Object.entries(channels)) {
          if (
            channelConfig.dmPolicy === 'open' &&
            Array.isArray(channelConfig.allowFrom) &&
            channelConfig.allowFrom.includes('*')
          ) {
            hasOpenDmWildcard = true;
            break;
          }
        }
      }
      if (!hasOpenDmWildcard && dm?.policy === 'open') {
        const allowList = dm.allowFrom as string[] | undefined;
        if (Array.isArray(allowList) && allowList.includes('*')) {
          hasOpenDmWildcard = true;
        }
      }

      if (hasOpenDmWildcard) {
        findings.push({
          checkId: 'GATEWAY-007',
          name: 'Open DM Policy with Wildcard',
          description: 'Direct message policy allows messages from any source',
          category: 'gateway',
          severity: 'critical',
          passed: false,
          message: 'DM policy is open with wildcard allowFrom - anyone can message the agent',
          file: relativePath,
          fixable: false,
          fix: 'Replace wildcard "*" in allowFrom with specific allowed sender IDs or domains',
        });
      }

      // GATEWAY-008: Tailscale Funnel Exposure
      const tailscale = gateway?.tailscale as Record<string, unknown> | undefined;
      const tailscaleRoot = config.tailscale as Record<string, unknown> | undefined;
      const funnelEnabled = tailscale?.funnel === true || tailscaleRoot?.funnel === true;

      if (funnelEnabled) {
        findings.push({
          checkId: 'GATEWAY-008',
          name: 'Tailscale Funnel Exposure',
          description: 'Tailscale Funnel is enabled, exposing the agent to the public internet',
          category: 'gateway',
          severity: 'high',
          passed: false,
          message: 'Tailscale Funnel enabled - agent is publicly accessible from the internet',
          file: relativePath,
          fixable: false,
          fix: 'Disable Tailscale Funnel unless public access is intentional. Use Tailscale ACLs to restrict access.',
        });
      }

      // Write modified config back to file if any fixes were applied
      if (configModified) {
        try {
          await fs.writeFile(configFile, JSON.stringify(config, null, 2) + '\n');
          // Add a summary finding about what was fixed
          findings.push({
            checkId: 'FIX-SUMMARY',
            name: 'Auto-Fix Applied',
            description: 'Configuration was automatically remediated',
            category: 'gateway',
            severity: 'low',
            passed: true,
            message: `Applied ${fixesApplied.length} fix(es): ${fixesApplied.join('; ')}`,
            file: relativePath,
            fixable: false,
            fix: 'Use `hackmyagent rollback` to undo these changes if needed',
          });
        } catch (writeError) {
          findings.push({
            checkId: 'FIX-ERROR',
            name: 'Auto-Fix Failed',
            description: 'Could not write configuration changes',
            category: 'gateway',
            severity: 'medium',
            passed: false,
            message: `Failed to write fixes to ${relativePath}: ${writeError instanceof Error ? writeError.message : 'Unknown error'}`,
            file: relativePath,
            fixable: false,
            fix: 'Check file permissions and try again',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }

  /**
   * Find files matching a pattern recursively (max depth 3, skips node_modules/.git)
   */
  private async findFilesMatching(
    targetDir: string,
    patterns: string[],
    maxDepth: number = 3
  ): Promise<string[]> {
    const matchedFiles: string[] = [];

    const scanDir = async (dir: string, currentDepth: number): Promise<void> => {
      if (currentDepth > maxDepth) return;

      let entries;
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        // Skip symlinks to prevent path traversal
        if (entry.isSymbolicLink()) {
          continue;
        }

        const entryName = entry.name;
        const fullPath = path.join(dir, entryName);

        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, targetDir)) {
          continue;
        }

        // Skip node_modules and .git directories
        if (entryName === 'node_modules' || entryName === '.git') {
          continue;
        }

        let stat;
        try {
          stat = await fs.stat(fullPath);
        } catch {
          continue;
        }

        if (stat.isDirectory()) {
          await scanDir(fullPath, currentDepth + 1);
        } else if (stat.isFile()) {
          // Check if filename matches any pattern
          const lowerName = entryName.toLowerCase();
          for (const pattern of patterns) {
            if (lowerName.includes(pattern.toLowerCase())) {
              matchedFiles.push(fullPath);
              break;
            }
          }
        }
      }
    };

    await scanDir(targetDir, 0);
    return matchedFiles;
  }

  /**
   * OpenClaw config security checks (CONFIG-001 to CONFIG-006)
   */
  private async checkOpenclawConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // CONFIG-001: Session File Exposure
    const sessionPatterns = [
      'whatsapp-session',
      'discord-token',
      'telegram-session',
      'slack-token',
      'session.json',
    ];
    const sessionFiles = await this.findFilesMatching(targetDir, sessionPatterns);
    for (const sessionFile of sessionFiles) {
      const relativePath = path.relative(targetDir, sessionFile);
      findings.push({
        checkId: 'CONFIG-001',
        name: 'Session File Exposure',
        description: 'Session/token file found that may contain sensitive credentials',
        category: 'config',
        severity: 'critical',
        passed: false,
        message: `Session/token file exposed: ${path.basename(sessionFile)}`,
        file: relativePath,
        fixable: false,
        fix: 'Move session files outside the project directory or add to .gitignore',
      });
    }

    // CONFIG-002: SOUL.md Injection Vectors
    const soulFiles = await this.findFilesMatching(targetDir, ['SOUL.md']);
    for (const soulFile of soulFiles) {
      const relativePath = path.relative(targetDir, soulFile);
      let content: string;
      try {
        const stats = await fs.stat(soulFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(soulFile, 'utf-8');
      } catch {
        continue;
      }

      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'CONFIG-002',
            name: 'SOUL.md Injection Vectors',
            description: 'SOUL.md contains potential prompt injection patterns',
            category: 'config',
            severity: 'high',
            passed: false,
            message: `Prompt injection pattern detected: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Review and remove suspicious patterns from SOUL.md',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-003: Daemon Running as Root
    const daemonPatterns = ['daemon.sh', 'start.sh', 'run.sh'];
    const daemonFiles = await this.findFilesMatching(targetDir, daemonPatterns);
    const rootPatterns = [/\bsudo\b/gi, /User=root/gi, /uid=0/gi];
    for (const daemonFile of daemonFiles) {
      const relativePath = path.relative(targetDir, daemonFile);
      let content: string;
      try {
        const stats = await fs.stat(daemonFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(daemonFile, 'utf-8');
      } catch {
        continue;
      }

      for (const pattern of rootPatterns) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'CONFIG-003',
            name: 'Daemon Running as Root',
            description: 'Daemon script runs with root privileges',
            category: 'config',
            severity: 'critical',
            passed: false,
            message: `Root privilege pattern found: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Run daemon as non-root user with minimal privileges',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-004: Plaintext API Keys
    const envFiles = await this.findFilesMatching(targetDir, ['.env']);
    for (const envFile of envFiles) {
      const relativePath = path.relative(targetDir, envFile);
      let content: string;
      try {
        const stats = await fs.stat(envFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(envFile, 'utf-8');
      } catch {
        continue;
      }

      for (const { name, pattern } of CREDENTIAL_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'CONFIG-004',
            name: 'Plaintext API Keys',
            description: 'Plaintext API key found in environment file',
            category: 'config',
            severity: 'critical',
            passed: false,
            message: `${name} found in plaintext`,
            file: relativePath,
            fixable: false,
            fix: 'Use a secrets manager or ensure .env is in .gitignore',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-005: Memory Poisoning Patterns
    const memoryFiles = await this.findFilesMatching(targetDir, ['memory.json']);
    const memoryPoisonPatterns = [
      ...PROMPT_INJECTION_PATTERNS,
      /\bbase64\b/gi,
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
    ];
    for (const memoryFile of memoryFiles) {
      const relativePath = path.relative(targetDir, memoryFile);
      let content: string;
      try {
        const stats = await fs.stat(memoryFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(memoryFile, 'utf-8');
      } catch {
        continue;
      }

      for (const pattern of memoryPoisonPatterns) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'CONFIG-005',
            name: 'Memory Poisoning Patterns',
            description: 'memory.json contains suspicious patterns that could poison agent memory',
            category: 'config',
            severity: 'high',
            passed: false,
            message: `Suspicious pattern in memory: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Review and sanitize memory.json contents',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-006: Moltbook Integration Risk
    const openclawConfigFiles = await this.findFilesMatching(targetDir, ['openclaw.json']);
    for (const configFile of openclawConfigFiles) {
      const relativePath = path.relative(targetDir, configFile);
      let config: Record<string, unknown>;
      try {
        const stats = await fs.stat(configFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        const content = await fs.readFile(configFile, 'utf-8');
        config = JSON.parse(content);
      } catch {
        continue;
      }

      const moltbook = config.moltbook as Record<string, unknown> | undefined;
      if (moltbook && moltbook.enabled === true && moltbook.autoFollow === true) {
        findings.push({
          checkId: 'CONFIG-006',
          name: 'Moltbook Integration Risk',
          description: 'Moltbook auto-follow enabled, allowing automatic following of untrusted agents',
          category: 'config',
          severity: 'high',
          passed: false,
          message: 'Moltbook enabled with autoFollow - may auto-follow untrusted agents',
          file: relativePath,
          fixable: false,
          fix: 'Disable autoFollow or review moltbook security settings',
        });
      }

      // CONFIG-007: Unrestricted Elevated Execution
      const tools = config.tools as Record<string, unknown> | undefined;
      const elevated = tools?.elevated as Record<string, unknown> | undefined;
      const exec = config.exec as Record<string, unknown> | undefined;
      const execApprovals = exec?.approvals as Record<string, unknown> | undefined;
      const hasUnrestrictedExec =
        elevated?.defaultLevel === 'full' ||
        execApprovals?.set === 'off';

      if (hasUnrestrictedExec) {
        findings.push({
          checkId: 'CONFIG-007',
          name: 'Unrestricted Elevated Execution',
          description: 'Elevated execution is set to full access without restrictions or approvals are bypassed',
          category: 'config',
          severity: 'critical',
          passed: false,
          message: elevated?.defaultLevel === 'full'
            ? 'tools.elevated.defaultLevel is "full" - all tools run with maximum privileges'
            : 'exec.approvals.set is "off" - execution approval is bypassed',
          file: relativePath,
          fixable: false,
          fix: 'Set tools.elevated.defaultLevel to "restricted" and enable exec.approvals',
        });
      }

      // CONFIG-008: Sandbox Disabled
      const sandbox = config.sandbox as Record<string, unknown> | undefined;
      const toolExec = tools?.exec as Record<string, unknown> | undefined;
      const sandboxDisabled =
        sandbox?.enabled === false ||
        toolExec?.sandbox === false;

      if (sandboxDisabled) {
        findings.push({
          checkId: 'CONFIG-008',
          name: 'Sandbox Disabled',
          description: 'Sandbox execution environment is explicitly disabled in config',
          category: 'config',
          severity: 'high',
          passed: false,
          message: sandbox?.enabled === false
            ? 'sandbox.enabled is false - code runs without isolation'
            : 'tools.exec.sandbox is false - tool execution is not sandboxed',
          file: relativePath,
          fixable: false,
          fix: 'Enable sandbox: set sandbox.enabled to true or tools.exec.sandbox to true',
        });
      }

      // CONFIG-009: Weak Gateway Token
      const gatewayConfig = config.gateway as Record<string, unknown> | undefined;
      const gatewayAuth = gatewayConfig?.auth as Record<string, unknown> | undefined;
      const tokenValue = (gatewayAuth?.token as string) || (config.token as string);
      if (
        typeof tokenValue === 'string' &&
        tokenValue.length > 0 &&
        tokenValue.length < 24 &&
        !tokenValue.startsWith('${')
      ) {
        findings.push({
          checkId: 'CONFIG-009',
          name: 'Weak Gateway Token',
          description: 'Gateway authentication token is too short (< 24 characters)',
          category: 'config',
          severity: 'high',
          passed: false,
          message: `Token is only ${tokenValue.length} characters - minimum 24 recommended`,
          file: relativePath,
          fixable: false,
          fix: 'Generate a stronger token: openssl rand -base64 32',
        });
      }
    }

    return findings;
  }

  /**
   * OpenClaw supply chain security checks (SUPPLY-001 to SUPPLY-004)
   */
  private async checkOpenclawSupplyChain(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const skillFiles = await this.findSkillFiles(targetDir);

    // Known malicious skill patterns from ClawHavoc campaign
    const clawHavocPatterns = [
      'polymarket',
      'better-polymarket',
      'crypto-tracker',
      'solana-tracker',
      'phantom-wallet',
      'youtube-downloader',
      'clawhub',
      'clawhub1',
      'clawhubb',
      'cllawhub',
      'clawhub-official',
      'openclaw-official',
      'openclaw1',
      'opennclaw',
      'insiderwallet',
      'wallet-finder',
      'crypto-insider',
    ];

    for (const skillFile of skillFiles) {
      const relativePath = path.relative(targetDir, skillFile);

      let content: string;
      try {
        const stats = await fs.stat(skillFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
          });
          continue;
        }
        content = await fs.readFile(skillFile, 'utf-8');
      } catch {
        continue;
      }

      // Parse YAML frontmatter
      const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
      const frontmatter = frontmatterMatch ? frontmatterMatch[1] : '';

      // Extract skill name from filename or frontmatter
      const skillNameMatch = frontmatter.match(/^name:\s*(.+)$/m);
      const skillName = skillNameMatch
        ? skillNameMatch[1].trim().replace(/["']/g, '').toLowerCase()
        : path.basename(path.dirname(skillFile)).toLowerCase();

      // SUPPLY-001: Unverified Publisher
      const hasPublisher = /^publisher:\s*.+$/m.test(frontmatter);
      const hasPublisherVerified = /^publisher_verified:\s*true$/m.test(frontmatter);

      findings.push({
        checkId: 'SUPPLY-001',
        name: 'Unverified Publisher',
        description: 'Skill publisher identity has not been verified',
        category: 'supply',
        severity: 'high',
        passed: hasPublisher && hasPublisherVerified,
        message: hasPublisher && hasPublisherVerified
          ? 'Skill publisher is verified'
          : hasPublisher
            ? 'Skill has publisher but publisher_verified is not true'
            : 'Skill lacks publisher metadata - cannot verify source',
        file: relativePath,
        fixable: false,
        fix: 'Add publisher: and publisher_verified: true to skill frontmatter after verification',
      });

      // SUPPLY-002: Skill Not in Registry
      const hasRegistryAttestation = /^registry_attestation:\s*.+$/m.test(frontmatter);

      findings.push({
        checkId: 'SUPPLY-002',
        name: 'Skill Not in Registry',
        description: 'Skill has not been registered with a trusted skill registry',
        category: 'supply',
        severity: 'medium',
        passed: hasRegistryAttestation,
        message: hasRegistryAttestation
          ? 'Skill has registry attestation'
          : 'Skill lacks registry_attestation - not listed in trusted registry',
        file: relativePath,
        fixable: false,
        fix: 'Register skill with a trusted registry (e.g., clawhub.io, skillregistry.openclaw.org)',
      });

      // SUPPLY-003: Known Malicious Skill Pattern (ClawHavoc campaign)
      let isMaliciousMatch = false;
      let matchedPattern = '';

      for (const pattern of clawHavocPatterns) {
        // Check for exact match or substring
        if (skillName.includes(pattern)) {
          isMaliciousMatch = true;
          matchedPattern = pattern;
          break;
        }

        // Check for typosquatting (Levenshtein distance <= 1)
        const distance = this.levenshteinDistance(skillName, pattern);
        if (distance <= 1 && distance > 0) {
          isMaliciousMatch = true;
          matchedPattern = `${skillName} (similar to ${pattern})`;
          break;
        }
      }

      if (isMaliciousMatch) {
        findings.push({
          checkId: 'SUPPLY-003',
          name: 'Known Malicious Skill Pattern',
          description: 'Skill matches known malicious patterns from ClawHavoc campaign',
          category: 'supply',
          severity: 'critical',
          passed: false,
          message: `Skill matches known malicious pattern: "${matchedPattern}"`,
          file: relativePath,
          fixable: false,
          fix: 'Remove this skill -- it matches known malware from the ClawHavoc campaign',
        });
      }

      // SUPPLY-004: Version Drift Detection
      const hasInstalledHash = /^installed_hash:\s*.+$/m.test(frontmatter);

      findings.push({
        checkId: 'SUPPLY-004',
        name: 'Version Drift Detection',
        description: 'Skill lacks installed_hash for detecting unauthorized modifications',
        category: 'supply',
        severity: 'high',
        passed: hasInstalledHash,
        message: hasInstalledHash
          ? 'Skill has installed_hash for integrity verification'
          : 'Skill lacks installed_hash - cannot detect version drift or tampering',
        file: relativePath,
        fixable: false,
        fix: 'Add installed_hash: with SHA-256 hash of the original skill content',
      });

      // SUPPLY-005: ClawHavoc C2 IP
      for (const ip of CLAWHAVOC_C2_IPS) {
        if (content.includes(ip)) {
          findings.push({
            checkId: 'SUPPLY-005',
            name: 'ClawHavoc C2 IP Detected',
            description: 'Skill contains known ClawHavoc command-and-control IP address',
            category: 'supply',
            severity: 'critical',
            passed: false,
            message: `Known C2 IP address found: ${ip}`,
            file: relativePath,
            fixable: false,
            fix: 'Remove this skill -- contains known malware C2 infrastructure',
          });
          break;
        }
      }

      // SUPPLY-006: Malware Filenames
      for (const filename of CLAWHAVOC_MALICIOUS_FILES) {
        if (content.toLowerCase().includes(filename.toLowerCase())) {
          findings.push({
            checkId: 'SUPPLY-006',
            name: 'ClawHavoc Malware Filename',
            description: 'Skill references known ClawHavoc malware payload filename',
            category: 'supply',
            severity: 'critical',
            passed: false,
            message: `Known malware filename referenced: "${filename}"`,
            file: relativePath,
            fixable: false,
            fix: 'Remove this skill -- references known malware payload',
          });
          break;
        }
      }

      // SUPPLY-007: ClickFix Pattern
      for (const pattern of CLAWHAVOC_CLICKFIX_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'SUPPLY-007',
            name: 'ClawHavoc ClickFix Pattern',
            description: 'Skill contains social engineering instructions to execute malware',
            category: 'supply',
            severity: 'high',
            passed: false,
            message: `ClickFix social engineering pattern detected: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Review and remove suspicious download/execute instructions',
          });
          break;
        }
      }

      // SUPPLY-008: Suspicious Archive Password
      const archiveMatch = content.match(CLAWHAVOC_ARCHIVE_PASSWORD);
      if (archiveMatch) {
        findings.push({
          checkId: 'SUPPLY-008',
          name: 'Suspicious Archive Password',
          description: 'Skill contains password-protected archive reference typical of malware distribution',
          category: 'supply',
          severity: 'high',
          passed: false,
          message: `Suspicious archive password pattern: "${archiveMatch[0]}"`,
          file: relativePath,
          fixable: false,
          fix: 'Investigate password-protected archive reference - common malware distribution technique',
        });
      }
    }

    return findings;
  }

  /**
   * OpenClaw CVE-specific checks (CVE-001, CVE-002, CVE-003, CVE-004)
   */
  private async checkOpenclawCVE(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // CVE-001: Vulnerable OpenClaw Version
    const pkgJsonPath = path.join(targetDir, 'package.json');
    try {
      const pkgContent = await fs.readFile(pkgJsonPath, 'utf-8');
      const pkg = JSON.parse(pkgContent);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      const openclawVersion = deps?.openclaw || deps?.['@openclaw/core'];

      if (openclawVersion) {
        // Extract numeric version (strip ^ ~ >= etc.)
        const versionMatch = openclawVersion.match(/(\d{4})\.(\d{1,2})\.(\d{1,2})/);
        if (versionMatch) {
          const year = parseInt(versionMatch[1], 10);
          const month = parseInt(versionMatch[2], 10);
          const day = parseInt(versionMatch[3], 10);

          // Patch release: v2026.1.29
          const isVulnerable =
            year < 2026 ||
            (year === 2026 && month < 1) ||
            (year === 2026 && month === 1 && day < 29);

          findings.push({
            checkId: 'CVE-001',
            name: 'CVE-2026-25253: WebSocket Hijacking RCE',
            description: 'OpenClaw version vulnerable to CVE-2026-25253 (CVSS 8.8) - WebSocket hijacking enables 1-click RCE',
            category: 'cve',
            severity: 'critical',
            passed: !isVulnerable,
            message: isVulnerable
              ? `OpenClaw ${openclawVersion} is vulnerable to CVE-2026-25253 - upgrade to v2026.1.29+`
              : `OpenClaw ${openclawVersion} includes CVE-2026-25253 fix`,
            file: 'package.json',
            fixable: false,
            fix: 'Upgrade openclaw to v2026.1.29 or later: npm install openclaw@latest',
          });
          // CVE-003: OS Command Injection via SSH Path (same fix version)
          if (isVulnerable) {
            findings.push({
              checkId: 'CVE-003',
              name: 'CVE-2026-25157: OS Command Injection via SSH Path',
              description: 'OpenClaw version vulnerable to CVE-2026-25157 (CVSS 7.8) - unescaped project path enables command injection on SSH hosts',
              category: 'cve',
              severity: 'high',
              passed: false,
              message: `OpenClaw ${openclawVersion} is vulnerable to CVE-2026-25157 - upgrade to v2026.1.29+`,
              file: 'package.json',
              fixable: false,
              fix: 'Upgrade openclaw to v2026.1.29 or later: npm install openclaw@latest',
            });
          } else {
            findings.push({
              checkId: 'CVE-003',
              name: 'CVE-2026-25157: OS Command Injection via SSH Path',
              description: 'OpenClaw version includes CVE-2026-25157 fix',
              category: 'cve',
              severity: 'high',
              passed: true,
              message: `OpenClaw ${openclawVersion} includes CVE-2026-25157 fix`,
              file: 'package.json',
              fixable: false,
              fix: 'No action needed',
            });
          }

          // CVE-004: Docker PATH Command Injection (same fix version)
          if (isVulnerable) {
            findings.push({
              checkId: 'CVE-004',
              name: 'CVE-2026-24763: Docker PATH Command Injection',
              description: 'OpenClaw version vulnerable to CVE-2026-24763 (CVSS 8.8) - unsafe PATH handling enables command injection in Docker sandbox',
              category: 'cve',
              severity: 'critical',
              passed: false,
              message: `OpenClaw ${openclawVersion} is vulnerable to CVE-2026-24763 - upgrade to v2026.1.29+`,
              file: 'package.json',
              fixable: false,
              fix: 'Upgrade openclaw to v2026.1.29 or later: npm install openclaw@latest',
            });
          } else {
            findings.push({
              checkId: 'CVE-004',
              name: 'CVE-2026-24763: Docker PATH Command Injection',
              description: 'OpenClaw version includes CVE-2026-24763 fix',
              category: 'cve',
              severity: 'critical',
              passed: true,
              message: `OpenClaw ${openclawVersion} includes CVE-2026-24763 fix`,
              file: 'package.json',
              fixable: false,
              fix: 'No action needed',
            });
          }
        }
      }
    } catch {
      // No package.json or parse error - skip CVE checks
    }

    // CVE-002: Control UI Origin Restrictions (defense-in-depth)
    const configFiles = await this.findGatewayConfigFiles(targetDir);
    for (const configFile of configFiles) {
      const relativePath = path.relative(targetDir, configFile);
      try {
        const stats = await fs.stat(configFile);
        if (stats.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(configFile, 'utf-8');
        const config = JSON.parse(content);

        const gateway = config.gateway as Record<string, unknown> | undefined;
        const controlUi = gateway?.controlUi as Record<string, unknown> | undefined;
        const hasAllowedOrigins = controlUi?.allowedOrigins && Array.isArray(controlUi.allowedOrigins) && controlUi.allowedOrigins.length > 0;

        // Only flag if auth is configured (no auth = lower risk)
        const hasAuth = gateway?.auth || config.auth || config.token || gateway?.token;

        if (hasAuth && !hasAllowedOrigins) {
          findings.push({
            checkId: 'CVE-002',
            name: 'Control UI Origin Restrictions Not Configured',
            description: 'Auth is configured but controlUi.allowedOrigins is not set - adding explicit origin restrictions provides defense-in-depth',
            category: 'cve',
            severity: 'medium',
            passed: false,
            message: 'Auth configured without controlUi.allowedOrigins - consider adding explicit origin restrictions for defense-in-depth',
            file: relativePath,
            fixable: false,
            fix: 'Add gateway.controlUi.allowedOrigins with your allowed origins (e.g., ["http://localhost:3000"])',
          });
        } else if (hasAuth && hasAllowedOrigins) {
          findings.push({
            checkId: 'CVE-002',
            name: 'Control UI Origin Restrictions Configured',
            description: 'Control UI origin restrictions are configured',
            category: 'cve',
            severity: 'medium',
            passed: true,
            message: 'controlUi.allowedOrigins is configured',
            file: relativePath,
            fixable: false,
            fix: 'No action needed',
          });
        }
      } catch {
        continue;
      }
    }

    return findings;
  }
}
