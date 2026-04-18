/**
 * Hardening Scanner
 * Scans for security issues and optionally auto-fixes them
 */

import * as fs from 'fs/promises';
import * as crypto from 'crypto';
import * as path from 'path';
import type { ScanResult, SecurityFinding, Severity, ProjectType } from './security-check';
import { StructuralAnalyzer, toSecurityFindings, LLMAnalyzer } from '../semantic';
import { enrichWithTaxonomy } from './taxonomy';
import { classifySkillSection, isLikelyFalsePositive } from './skill-context';
import { isCorpusPath, isTestPath, isExamplePath } from './path-context';
import { scanAssembly } from '../lifecycle/assembly-scanner';
import {
  parseDeclaredCapabilities as parseSkillDeclaredCaps,
  inferActualCapabilities,
  validateCapabilities,
} from './skill-capability-validator';

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

  // Skill/config checks - apply to all because if these files exist, they matter
  'SKILL-': ['all'], // Skill file security (fires only when skill files exist)
  'HEARTBEAT-': ['all'], // Heartbeat/periodic task security (fires only when HEARTBEAT.md exists)
  'GATEWAY-': ['openclaw'], // Gateway configuration security
  'CONFIG-': ['all'], // Configuration file security (fires only when config files exist)
  'SUPPLY-': ['all'], // Supply chain security (fires only when skill files exist)
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

  // Unicode steganography - applies to all projects
  'UNICODE-STEGO-': ['all'],

  // Agent memory/context checks
  'MEM-': ['all'],
  // RAG poisoning checks
  'RAG-': ['all'],
  // Agent identity checks
  'AIM-': ['all'],
  // Agent DNA integrity checks
  'DNA-': ['all'],
  // Skill memory manipulation checks
  'SKILL-MEM-': ['openclaw', 'mcp'],
  // NemoClaw/sandbox static analysis checks
  'NEMO-': ['all'],

  // AI infrastructure exposure checks (research gap coverage)
  'LLM-': ['all'], // LLM inference endpoint exposure
  'AITOOL-': ['all'], // AI tooling exposure (Jupyter, Gradio, etc.)
  'A2A-': ['all'], // A2A protocol exposure
  'WEBCRED-': ['all'], // Credentials in web-served files

  // Code injection and supply chain checks
  'CODEINJ-': ['all'], // Code injection via exec with interpolation
  'INSTALL-': ['all'], // Unsafe install scripts (curl|sh)
  'CLIPASS-': ['all'], // Credentials passed as CLI arguments
  'INTEGRITY-': ['all'], // Integrity check bypass
  'TOCTOU-': ['all'], // Time-of-check-time-of-use race conditions
  'TMPPATH-': ['all'], // Hardcoded /tmp path attacks
  'DOCKERINJ-': ['all'], // Docker exec with variable injection
  'ENVLEAK-': ['all'], // Environment variable leakage to child processes
  'SANDBOX-005': ['openclaw', 'mcp'], // Messaging API pre-allowed in sandbox
  'WEBEXPOSE-': ['all'], // Sensitive files in web-served directories
  'AGENT-CRED-': ['all'], // Missing credential protection in system prompts
  'SOUL-OVERRIDE-': ['all'], // Skill content overriding SOUL.md
  'SOUL-': ['all'],          // SOUL governance gap checks

  // Context lifecycle checks (assembly-stage analysis)
  'LIFECYCLE-': ['all'],
};

/** Scan depth for CAAT tiered scanning */
export type ScanDepth = 'quick' | 'standard' | 'deep';

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
  /**
   * CAAT scan depth tier:
   *   quick    — config checks, credential detection, basic file analysis only (Tier 4)
   *   standard — all hardening checks + dependency audit (default, Tier 2-3)
   *   deep     — everything + LLM semantic analysis + attack simulation (Tier 1)
   */
  scanDepth?: ScanDepth;
  /** Progress callback for long-running operations */
  onProgress?: (message: string) => void;
  /** CLI command prefix for fix messages (default: 'hackmyagent') */
  cliName?: string;
  /**
   * Set to true when scanning a downloaded npm/registry package (not a local project).
   * Suppresses checks that only make sense for source repos (GIT-001, GIT-002, GIT-003).
   */
  isNpmPackage?: boolean;
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
  // Match .env as a standalone file reference, not as part of process.env or documentation
  // like ".env.example in sync" or "set in .env.local"
  /(?:^|[\s"'`(])\.env(?:\.local|\.production|\.development)?(?:[\s"'`)]|$)/gi,
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

/**
 * Standalone scoring function using exponential decay with governance weight.
 * This is the canonical scoring formula — all score paths must use it.
 *
 * Accepts findings with at minimum: { passed?, fixed?, severity, category, checkId }.
 *
 * Per-check capping: only the first MAX_FINDINGS_PER_CHECK instances of each
 * unique checkId contribute to the weighted sum at full weight. Additional
 * instances contribute at a steeply diminished rate (10%). This prevents a
 * single pattern-match check (e.g. AST-CRED-001) from dominating the score
 * when it fires across dozens of files in a large repository. All findings
 * are still reported — only the score contribution is capped.
 */
export function calculateSecurityScore(findings: Array<{ passed?: boolean; fixed?: boolean; severity: string; category?: string; checkId?: string }>): {
  score: number;
  maxScore: number;
} {
  const GOVERNANCE_CATEGORIES = new Set(['governance', 'Governance', 'injection-hardening', 'trust-hierarchy']);
  const GOVERNANCE_PREFIXES = ['AST-GOV', 'AST-GOVERN', 'AST-PROMPT', 'AST-HEARTBEAT'];
  const GOVERNANCE_WEIGHT = 0.4;
  const DECAY_CONSTANT = 150;
  const MAX_FINDINGS_PER_CHECK = 3;
  const OVERFLOW_WEIGHT = 0.1; // 10% weight for findings beyond the cap

  // Count occurrences per checkId to apply diminishing returns
  const checkIdCounts = new Map<string, number>();

  let weightedSum = 0;
  for (const finding of findings) {
    if (!finding.passed && !finding.fixed) {
      const checkId = finding.checkId || '_unknown_';
      const count = (checkIdCounts.get(checkId) || 0) + 1;
      checkIdCounts.set(checkId, count);

      const isGovernance = GOVERNANCE_CATEGORIES.has(finding.category || '') ||
        GOVERNANCE_PREFIXES.some(p => (finding.checkId || '').startsWith(p));
      const governanceMultiplier = isGovernance ? GOVERNANCE_WEIGHT : 1;
      const capMultiplier = count <= MAX_FINDINGS_PER_CHECK ? 1 : OVERFLOW_WEIGHT;
      const sevWeight = SEVERITY_WEIGHTS[finding.severity as Severity] ?? 0;
      weightedSum += sevWeight * governanceMultiplier * capMultiplier;
    }
  }

  const score = weightedSum === 0
    ? 100
    : Math.round(100 * Math.exp(-weightedSum / DECAY_CONSTANT));

  return { score, maxScore: 100 };
}

/**
 * Check if a finding applies to the given project type based on the
 * CHECK_PROJECT_TYPES map. Exported so CLI can filter findings after
 * NanoMind merge.
 */
export function findingAppliesTo(finding: SecurityFinding, projectType: ProjectType): boolean {
  for (const [prefix, types] of Object.entries(CHECK_PROJECT_TYPES)) {
    if (finding.checkId.startsWith(prefix)) {
      if (types.includes('all')) return true;
      return types.includes(projectType);
    }
  }
  return true;
}

/**
 * Parsed .hmaignore rules split into path patterns and check ID patterns.
 * Check ID patterns start with `!` and support trailing `*` wildcards.
 * Example: `!SANDBOX-*` suppresses all SANDBOX checks.
 */
export interface HmaIgnoreRules {
  paths: string[];
  checkIds: string[];
}

/**
 * Load .hmaignore patterns from a target directory. Exported so CLI
 * can re-apply ignore filtering after NanoMind merge.
 */
export async function loadHmaIgnore(targetDir: string): Promise<HmaIgnoreRules> {
  const ignorePath = path.join(targetDir, '.hmaignore');
  try {
    const content = await fs.readFile(ignorePath, 'utf-8');
    const lines = content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    return {
      paths: lines.filter(l => !l.startsWith('!')),
      checkIds: lines.filter(l => l.startsWith('!')).map(l => l.slice(1)),
    };
  } catch {
    return { paths: [], checkIds: [] };
  }
}

/**
 * Check if a file path matches any .hmaignore path pattern. Exported so CLI
 * can filter findings after NanoMind merge.
 */
export function isPathIgnored(filePath: string, ignoredPaths: string[]): boolean {
  if (!filePath || ignoredPaths.length === 0) return false;
  const normalized = filePath.replace(/\\/g, '/');
  return ignoredPaths.some(pattern => {
    const normalizedPattern = pattern.replace(/\\/g, '/').replace(/\/$/, '');
    return normalized.startsWith(normalizedPattern + '/') || normalized === normalizedPattern;
  });
}

/**
 * Check if a checkId matches any .hmaignore check ID pattern.
 * Supports exact match and trailing `*` wildcard (e.g. `SANDBOX-*`).
 */
export function isCheckIgnored(checkId: string, ignoredChecks: string[]): boolean {
  if (!checkId || ignoredChecks.length === 0) return false;
  return ignoredChecks.some(pattern => {
    if (pattern.endsWith('*')) {
      return checkId.startsWith(pattern.slice(0, -1));
    }
    return checkId === pattern;
  });
}

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB max file size to prevent memory exhaustion
const MAX_LINE_LENGTH = 10000; // 10KB max line length for regex safety

/** Shell-escape a string for safe interpolation into advisory fix commands. */
function shellEscape(s: string): string {
  // Wrap in single quotes and escape embedded single quotes: ' -> '\''
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

/**
 * Check if a variation selector at position i in rawBuffer is a legitimate
 * emoji presentation selector (U+FE0F following an emoji base character).
 *
 * Emoji base characters that commonly precede FE0F:
 * - Keycap digits/symbols: 0-9, #, * (encoded as single ASCII bytes)
 * - BMP symbols: U+2600-27BF range (encoded as 3-byte UTF-8: E2 XX XX or E2 XX XX)
 * - SMP emoji: U+1F300-1FAFF (encoded as 4-byte UTF-8: F0 9F XX XX)
 */
function isEmojiVariationSelector(buf: Buffer, vsStart: number): boolean {
  // Walk backward to find the preceding character
  // The variation selector is at vsStart (3 bytes: EF B8 8F)
  // We need to check what character precedes it

  if (vsStart === 0) return false;

  // Check for 4-byte SMP emoji before (F0 9F XX XX) — most common case
  if (vsStart >= 4) {
    const b0 = buf[vsStart - 4];
    const b1 = buf[vsStart - 3];
    if (b0 === 0xF0 && b1 === 0x9F) return true; // U+1F000-1FFFF (emoji range)
  }

  // Check for 3-byte BMP symbol before (E2 XX XX) — symbols like warning, gear, etc.
  if (vsStart >= 3) {
    const b0 = buf[vsStart - 3];
    const b1 = buf[vsStart - 2];
    if (b0 === 0xE2) {
      // U+2600-27BF: Misc Symbols, Dingbats (E2 98 80 through E2 9E BF)
      if (b1 >= 0x98 && b1 <= 0x9E) return true;
      // U+2300-23FF: Misc Technical (E2 8C 80 through E2 8F BF) — includes hourglass, etc.
      if (b1 >= 0x8C && b1 <= 0x8F) return true;
    }
    // U+2700-27BF also encoded as E2 9C XX - E2 9E XX
    if (b0 === 0xE2 && b1 >= 0x9C && b1 <= 0x9E) return true;
  }

  // Check for 1-byte ASCII keycap base: #, *, 0-9
  if (vsStart >= 1) {
    const prev = buf[vsStart - 1];
    if (prev === 0x23 || prev === 0x2A) return true; // # or *
    if (prev >= 0x30 && prev <= 0x39) return true;   // 0-9
  }

  return false;
}

/**
 * Check if a Cyrillic character at position ci in chars[] is in a Cyrillic
 * text context (legitimate i18n) rather than mixed into a Latin word (attack).
 *
 * Looks at a window of nearby characters. If the neighborhood contains
 * mostly Cyrillic or other non-Latin chars, it's i18n. If surrounded by
 * Latin chars, it's a homoglyph attack.
 */
function isCyrillicInCyrillicContext(chars: string[], ci: number): boolean {
  // Look at a window of 10 chars in each direction
  const windowSize = 10;
  const start = Math.max(0, ci - windowSize);
  const end = Math.min(chars.length, ci + windowSize + 1);

  let latinCount = 0;
  let cyrillicCount = 0;

  for (let j = start; j < end; j++) {
    if (j === ci) continue;
    const cp = chars[j].codePointAt(0)!;
    // Latin letter
    if ((cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A)) {
      latinCount++;
    }
    // Any Cyrillic (U+0400-052F)
    if (cp >= 0x0400 && cp <= 0x052F) {
      cyrillicCount++;
    }
  }

  // If there are at least 3 other Cyrillic chars nearby, this is i18n text
  // (translations, i18n badges, etc. always have multiple Cyrillic chars together)
  if (cyrillicCount >= 3) return true;

  // If the immediate neighbors are both Latin, this is a homoglyph attack
  const prevLatin = ci > 0 && (() => {
    const cp = chars[ci - 1].codePointAt(0)!;
    return (cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A);
  })();
  const nextLatin = ci < chars.length - 1 && (() => {
    const cp = chars[ci + 1].codePointAt(0)!;
    return (cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A);
  })();

  if (prevLatin && nextLatin) return false; // Sandwiched in Latin = attack

  // Ambiguous case: not enough context. If there are ANY other Cyrillic
  // chars nearby, give benefit of the doubt (i18n).
  return cyrillicCount > 0;
}

export class HardeningScanner {
  private cliName = 'hackmyagent';
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
    // AI infrastructure files (research gap checks)
    'docker-compose.yml',
    'docker-compose.yaml',
    'compose.yml',
    'compose.yaml',
    'Dockerfile',
    'jupyter_notebook_config.py',
    'jupyter_server_config.py',
    '.well-known/agent.json',
    '.well-known/mcp.json',
  ];

  /**
   * Validate that a file path is within the target directory (no path traversal)
   */
  private isPathWithinDirectory(filePath: string, directory: string): boolean {
    const normalizedFile = path.resolve(filePath);
    const normalizedDir = path.resolve(directory);
    return normalizedFile.startsWith(normalizedDir + path.sep) || normalizedFile === normalizedDir;
  }

  /**
   * Load .hmaignore file from target directory.
   * Returns path patterns (plain lines) and check ID suppression patterns (lines starting with !).
   */
  private async loadHmaIgnore(targetDir: string): Promise<{ paths: string[]; checkIds: string[] }> {
    const ignorePath = path.join(targetDir, '.hmaignore');
    try {
      const content = await fs.readFile(ignorePath, 'utf-8');
      const lines = content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      const paths: string[] = [];
      const checkIds: string[] = [];
      for (const line of lines) {
        if (line.startsWith('!')) {
          // Check ID suppression pattern: strip the ! prefix, store uppercase
          checkIds.push(line.slice(1).toUpperCase());
        } else {
          paths.push(line);
        }
      }
      return { paths, checkIds };
    } catch {
      return { paths: [], checkIds: [] };
    }
  }

  /**
   * Check if a check ID matches any suppression pattern from .hmaignore.
   * Supports exact match and wildcard (*) at the end (e.g. SANDBOX-* matches SANDBOX-001).
   */
  private isCheckIdSuppressed(checkId: string, patterns: string[]): boolean {
    if (patterns.length === 0) return false;
    const upper = checkId.toUpperCase();
    return patterns.some(pattern => {
      if (pattern.includes('*')) {
        // Convert glob pattern to regex: escape special chars, replace * with .*
        const regexStr = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
        return new RegExp(regexStr).test(upper);
      }
      return upper === pattern;
    });
  }

  /**
   * Re-apply .hmaignore filters to a set of findings.
   * Call this after NanoMind merge overwrites result.findings with unfiltered data.
   */
  async reapplyIgnoreFilters(
    findings: SecurityFinding[],
    targetDir: string,
    additionalIgnorePaths?: string[],
  ): Promise<SecurityFinding[]> {
    const hmaIgnore = await this.loadHmaIgnore(targetDir);
    const allIgnoredPaths = [...hmaIgnore.paths, ...(additionalIgnorePaths || [])];
    const suppressedCheckPatterns = hmaIgnore.checkIds;

    if (allIgnoredPaths.length === 0 && suppressedCheckPatterns.length === 0) {
      return findings;
    }

    return findings.filter(f => {
      if (this.isCheckIdSuppressed(f.checkId, suppressedCheckPatterns)) return false;
      if (f.file && this.isPathIgnored(f.file, allIgnoredPaths)) return false;
      return true;
    });
  }

  /**
   * Check if a file path matches any .hmaignore pattern.
   */
  private isPathIgnored(filePath: string, ignoredPaths: string[]): boolean {
    if (!filePath || ignoredPaths.length === 0) return false;
    const normalized = filePath.replace(/\\/g, '/');
    return ignoredPaths.some(pattern => {
      const normalizedPattern = pattern.replace(/\\/g, '/').replace(/\/$/, '');
      return normalized.startsWith(normalizedPattern + '/') || normalized === normalizedPattern;
    });
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    const { targetDir, autoFix = false, dryRun = false, ignore = [], cliName = 'hackmyagent' } = options;
    this.cliName = cliName;

    // Resolve effective scan depth — --deep flag implies 'deep' depth
    const scanDepth: ScanDepth = options.scanDepth || (options.deep ? 'deep' : 'standard');
    const isQuick = scanDepth === 'quick';
    const isDeepScan = scanDepth === 'deep';

    // Load .hmaignore for path-based exclusions and check ID suppressions
    const hmaIgnore = await this.loadHmaIgnore(targetDir);
    // Merge with any programmatic ignorePaths
    const allIgnoredPaths = [...hmaIgnore.paths, ...(options.ignorePaths || [])];
    // Check ID suppression patterns from .hmaignore (supports wildcards)
    const suppressedCheckPatterns = hmaIgnore.checkIds;

    // Normalize ignore list to uppercase for case-insensitive matching
    // Merge CLI --ignore flags with .hmaignore !-prefixed check IDs
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

    // Git security checks (skip for downloaded npm packages — not a source repo)
    if (!options.isNpmPackage) {
      const gitFindings = await this.checkGitSecurity(targetDir, shouldFix);
      findings.push(...gitFindings);
    }

    // Network security checks
    const netFindings = await this.checkNetworkSecurity(targetDir, shouldFix);
    findings.push(...netFindings);

    // --- Standard and Deep checks (skipped in quick mode) ---
    if (!isQuick) {
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

    // Unicode steganography checks (GlassWorm detection)
    const unicodeStegoFindings = await this.checkUnicodeSteganography(targetDir, shouldFix);
    findings.push(...unicodeStegoFindings);

    // Memory/context poisoning checks
    const memFindings = await this.checkMemoryPoisoning(targetDir, shouldFix);
    findings.push(...memFindings);

    // RAG poisoning checks
    const ragFindings = await this.checkRAGPoisoning(targetDir, shouldFix);
    findings.push(...ragFindings);

    // Agent identity checks
    const aimFindings = await this.checkAgentIdentity(targetDir, shouldFix);
    findings.push(...aimFindings);

    // Agent DNA integrity checks
    const dnaFindings = await this.checkAgentDNA(targetDir, shouldFix);
    findings.push(...dnaFindings);

    // Skill memory manipulation checks
    const skillMemFindings = await this.checkSkillMemory(targetDir, shouldFix);
    findings.push(...skillMemFindings);

    // NemoClaw codebase pattern checks
    const nemoFindings = await this.checkNemoClawPatterns(targetDir, shouldFix);
    findings.push(...nemoFindings);

    // AI infrastructure exposure checks (research gap coverage)
    const llmFindings = await this.checkLLMExposure(targetDir, shouldFix);
    findings.push(...llmFindings);

    const aiToolFindings = await this.checkAIToolExposure(targetDir, shouldFix);
    findings.push(...aiToolFindings);

    const a2aFindings = await this.checkA2AExposure(targetDir, shouldFix);
    findings.push(...a2aFindings);

    const mcpDiscoveryFindings = await this.checkMCPDiscovery(targetDir, shouldFix);
    findings.push(...mcpDiscoveryFindings);

    const webCredFindings = await this.checkWebServedCredentials(targetDir, shouldFix);
    findings.push(...webCredFindings);

    // Code injection, supply chain, and operational security checks
    // NOTE: CODEINJ-001 removed — deduplicated with NEMO-005 (same detection)

    const installFindings = await this.checkInstallScripts(targetDir, shouldFix);
    findings.push(...installFindings);

    const cliPassFindings = await this.checkCLICredentialPassthrough(targetDir, shouldFix);
    findings.push(...cliPassFindings);

    const integrityFindings = await this.checkIntegrityBypass(targetDir, shouldFix);
    findings.push(...integrityFindings);

    const toctouFindings = await this.checkTOCTOU(targetDir, shouldFix);
    findings.push(...toctouFindings);

    // NOTE: TMPPATH-001 removed — deduplicated with NEMO-006 (same detection)

    const dockerInjFindings = await this.checkDockerInjection(targetDir, shouldFix);
    findings.push(...dockerInjFindings);

    // NOTE: ENVLEAK-001 removed — deduplicated with NEMO-007 (same detection)

    const sandboxMsgFindings = await this.checkSandboxMessaging(targetDir, shouldFix);
    findings.push(...sandboxMsgFindings);

    const webExposeFindings = await this.checkWebExposedFiles(targetDir, shouldFix);
    findings.push(...webExposeFindings);

    const soulOverrideFindings = await this.checkSoulOverride(targetDir, shouldFix);
    findings.push(...soulOverrideFindings);

    const soulGovFindings = await this.checkSoulGovernanceGaps(targetDir);
    findings.push(...soulGovFindings);

    const memSanitizeFindings = await this.checkMemoryStoreSanitization(targetDir, shouldFix);
    findings.push(...memSanitizeFindings);

    const agentCredFindings = await this.checkAgentCredentialProtection(targetDir, shouldFix);
    findings.push(...agentCredFindings);

    // Context lifecycle assembly checks (Stage 1)
    const lifecycleFindings = await this.checkContextLifecycle(targetDir, options);
    findings.push(...lifecycleFindings);
    } // end of standard/deep checks

    // Enrich findings with attack taxonomy mapping
    enrichWithTaxonomy(findings);

    // Layer 2: Structural analysis (standard and deep only)
    let layer2Count = 0;
    let layer3Count = 0;
    let llmCost: number | undefined;
    let cachedResults: number | undefined;
    if (!isQuick) {
    try {
      const structural = new StructuralAnalyzer();
      const structuralFindings = await structural.analyze(targetDir);
      const converted = toSecurityFindings(structuralFindings);
      findings.push(...converted);
      layer2Count = converted.length;
    } catch {
      // Structural analysis failure is non-fatal
    }
    }

    // Layer 3: LLM analysis (only in deep mode + API key)
    if ((isDeepScan || options.deep) && process.env.ANTHROPIC_API_KEY) {
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

    // Verify fixes: re-scan fixed files to confirm issues are actually resolved
    if (shouldFix) {
      const fixedFindings = findings.filter(f => f.fixed && f.file);
      if (fixedFindings.length > 0) {
        // Re-run a targeted scan (no fix, just detect) to verify
        const verifyScanner = new HardeningScanner();
        const verifyResult = await verifyScanner.scan({
          targetDir,
          autoFix: false,
          ignore: ignoredChecks.size > 0 ? [...ignoredChecks] : [],
          cliName: this.cliName,
        });

        // For each fixed finding, check if the same checkId still appears as failed
        const stillFailing = new Set(
          verifyResult.findings
            .filter(f => !f.passed && !f.fixed)
            .map(f => `${f.checkId}:${f.file}`)
        );

        for (const finding of fixedFindings) {
          const key = `${finding.checkId}:${finding.file}`;
          finding.fixVerified = !stillFailing.has(key);
          if (!finding.fixVerified) {
            finding.fixMessage = (finding.fixMessage || '') + ' [FIX NOT VERIFIED - issue may persist]';
          }
        }

        if (options.onProgress) {
          const verified = fixedFindings.filter(f => f.fixVerified).length;
          const total = fixedFindings.length;
          options.onProgress(`Fix verification: ${verified}/${total} fixes confirmed`);
        }
      }
    }

    // Filter findings to only show real, actionable issues:
    // 1. Only failed checks (passed: false)
    // 2. Only checks with a file path (concrete findings, not generic advice)
    // 3. Only checks that apply to this project type (e.g., no SQL checks on MCP servers)
    // 4. Filter out ignored checks
    let filteredFindings = findings.filter((f) => {
      // Keep fixed findings (so users can see what was fixed)
      // Otherwise, only show failed checks
      if (!f.fixed && f.passed) return false;

      // Only show concrete findings (has a file path)
      if (!f.file) return false;

      // Only show checks relevant to this project type
      if (!this.findingAppliesTo(f, projectType)) return false;

      // Filter out ignored checks (from --ignore flag)
      if (ignoredChecks.has(f.checkId.toUpperCase())) return false;

      // Filter out check IDs suppressed via .hmaignore (supports wildcards)
      if (this.isCheckIdSuppressed(f.checkId, suppressedCheckPatterns)) return false;

      // Filter out paths matching .hmaignore
      if (f.file && this.isPathIgnored(f.file, allIgnoredPaths)) return false;

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
      if (!platforms.includes('claude-code')) {
        platforms.push('claude-code');
      }
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
    const openclawIndicators = ['.openclaw', '.moltbot', '.clawdbot', 'SKILL.md', 'HEARTBEAT.md', 'openclaw.json'];
    for (const indicator of openclawIndicators) {
      try {
        await fs.access(path.join(targetDir, indicator));
        return 'openclaw';
      } catch {}
    }

    // Check for *.skill.md files at root level (OpenClaw skill project)
    try {
      const files = await fs.readdir(targetDir);
      if (files.some(f => f.endsWith('.skill.md'))) {
        return 'openclaw';
      }
    } catch {}

    // Check for skills/ subdirectory with SKILL.md files (common OpenClaw layout)
    try {
      await fs.access(path.join(targetDir, 'skills'));
      return 'openclaw';
    } catch {}

    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);

      // Check dependencies for framework detection
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      // Check for MCP server BEFORE cli -- MCP servers often have bin fields
      if (
        allDeps['@modelcontextprotocol/sdk'] ||
        allDeps['mcp'] ||
        pkg.name?.includes('mcp')
      ) {
        return 'mcp';
      }

      // Check for SDK/API client packages (requires 2+ signals).
      // Must run before CLI check: some SDKs ship CLI shims (e.g., openai)
      // but are primarily libraries.
      if (this.detectSDKPackage(pkg, allDeps)) {
        return 'sdk';
      }

      // Check if it's a CLI tool (has bin field)
      if (pkg.bin) {
        return 'cli';
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
   * Detect if a package is an SDK/API client. Requires 2+ independent
   * signals to avoid false positives (a random library with axios isn't
   * necessarily an SDK).
   */
  private detectSDKPackage(
    pkg: Record<string, unknown>,
    allDeps: Record<string, string>,
  ): boolean {
    const name = ((pkg.name as string) ?? '').toLowerCase();
    const desc = ((pkg.description as string) ?? '').toLowerCase();
    const keywords = (pkg.keywords as string[]) ?? [];

    // Signal 1: Package name contains SDK/client indicators
    const nameSignals = ['/sdk', '-sdk', '-client', 'api-client', '-api']
      .some(s => name.includes(s)) || name.endsWith('sdk');

    // Signal 2: Description mentions SDK/client/wrapper/library-for-API patterns
    const descSignals = [
      'sdk', 'client library', 'api client', 'api wrapper', 'official client',
      'library for the', 'library for', 'client for the', 'client for',
    ].some(s => desc.includes(s)) && desc.includes('api');

    // Signal 3: Has library exports (main/exports). SDKs may also ship CLI
    // shims, so we don't exclude on bin presence.
    const hasLibraryExports = !!(pkg.main || pkg.exports || pkg.module);

    // Signal 4: Depends on HTTP clients
    const httpDeps = ['node-fetch', 'axios', 'got', 'undici', 'cross-fetch', 'ky', 'superagent']
      .some(d => d in allDeps);

    // Signal 5: Keywords include sdk/client
    const kwSignals = keywords.some(k =>
      ['sdk', 'client', 'api-client', 'wrapper'].includes(k.toLowerCase()),
    );

    // Signal 6: Description pattern "for the X API" -- strong signal that
    // this is an API client library
    const forApiPattern = /\bfor\s+the\s+\w+\s+api\b/i.test(desc) ||
      /\b(official|typescript|javascript|node)\s+\w*\s*(library|client|sdk)\b/i.test(desc);

    const signalCount = [
      nameSignals,
      descSignals,
      hasLibraryExports && httpDeps,
      kwSignals,
      forApiPattern && hasLibraryExports,
    ].filter(Boolean).length;
    return signalCount >= 2;
  }

  /**
   * Check if a finding applies to the given project type
   */
  findingAppliesTo(finding: SecurityFinding, projectType: ProjectType): boolean {
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

              // Fix: replace credential with env var reference (but NOT in .env files
              // where the actual value is supposed to live)
              const isEnvFile = filename.startsWith('.env');
              if (autoFix && !isEnvFile) {
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

          const isEnvFile = filename.startsWith('.env');
          findings.push({
            checkId: 'CRED-001',
            name: 'Exposed Credential',
            description: `${keyNames.join(', ')} found in plaintext`,
            category: 'credentials',
            severity: 'critical',
            passed: fileModified,
            message: keyNames.join(', '),
            file: filename,
            line: firstLine,
            fixable: !isEnvFile, // .env files can't be auto-fixed (that's where values belong)
            fixed: fileModified,
            fix: isEnvFile
              ? 'Add .env to .gitignore to prevent committing secrets'
              : `${this.cliName} secure --fix`,
            guidance: isEnvFile
              ? 'Credentials in .env are expected but the file must be in .gitignore. Run `hackmyagent secure --fix` to create a .gitignore.'
              : 'Replaces hardcoded credentials with ${ENV_VAR} references. Store actual values in your .env file, which should be in .gitignore.',
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
          fix: 'npx secretless-ai init',
          guidance: 'CLAUDE.md is sent to your AI provider on every request. Credentials here are exposed to the model and extractable via prompt injection. Run opena2a protect . to encrypt them into a secure vault.',
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
          fix: `${this.cliName} secure --fix`,
          guidance: 'Root or home directory access lets MCP servers read/write any file on the system. Restrict to project-relative paths (./data or ./) to limit blast radius.',
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
          fix: 'Add "allowedCommands": ["ls", "cat", "grep"] to the shell server config in mcp.json',
          guidance: 'Unrestricted shell access lets the AI execute any command including destructive operations. Whitelisting specific commands limits what can be run.',
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
      guidance: 'Overly broad file permissions let any user on the system read sensitive config files that may contain credentials or API keys.',
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
        severity: 'low',
        passed: git001Fixed,
        message: 'Create .gitignore to protect sensitive files',
        file: '.gitignore',
        fixable: true,
        fixed: git001Fixed,
        fix: `${this.cliName} secure --fix`,
        guidance: 'Without .gitignore, sensitive files (.env, secrets.json, *.pem, *.key) can be accidentally committed to version control and exposed.',
      });
    }

    // GIT-002: Check for missing sensitive patterns in .gitignore
    // Only check if .gitignore exists — GIT-001 handles creation
    if (gitignoreExists) {
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
          fix: `${this.cliName} secure --fix`,
          guidance: `Missing patterns (${missingPatterns.join(', ')}) in .gitignore mean sensitive files could be accidentally committed and pushed to remote repositories.`,
        });
      }
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
        fix: `${this.cliName} secure --fix`,
        guidance: '.env files contain API keys and secrets. Without .gitignore protection, a single git add . can expose all credentials in your repository history.',
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
        fix: `${this.cliName} secure --fix`,
        guidance: 'Binding to 0.0.0.0 exposes the server to the entire network. Use 127.0.0.1 for local-only access. If remote access is needed, use a reverse proxy with authentication.',
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
        fix: 'Update URL to https:// in mcp.json',
        guidance: 'HTTP traffic is unencrypted and vulnerable to man-in-the-middle attacks. An attacker on the network can intercept and modify MCP server communications.',
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
        fix: `${this.cliName} secure --fix`,
        guidance: 'Hardcoded API keys in mcp.json are exposed to anyone with repo access. Run opena2a protect . to encrypt them into a secure vault — keys are injected at runtime, never stored as plaintext.',
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
        fix: 'openssl rand -base64 24',
        guidance: 'Default passwords (postgres, admin, root, etc.) are the first thing attackers try. Generate a strong random password and update mcp.json.',
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
        fix: 'Replace "*" with specific tool names in allowedTools (e.g., ["read_file", "list_directory"])',
        guidance: 'Wildcard tool access gives the AI unrestricted capabilities. Limit to only the tools your workflow actually needs to reduce attack surface.',
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
        fix: 'Replace Bash(*) with Bash(npm test) and Read(*) with Read(/src/**) in .claude/settings.json',
        guidance: 'Wildcard permissions give the AI unrestricted shell, read, or write access. Scope each permission to the specific commands and paths your workflow needs.',
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
        fix: 'Remove rm -rf, sudo, chmod 777 patterns from the allow list in .claude/settings.json',
        guidance: 'Allowing destructive commands means a single AI mistake can delete files, escalate privileges, or weaken permissions. Restrict to safe, reversible operations.',
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
        ? 'Cursor rules contain exposed credentials'
        : 'No credentials found in Cursor rules',
      fixable: false,
      fix: hasCredentialsInRules ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'Cursor rules files are often committed to git. Credentials embedded there get pushed to remotes where anyone with repo access can extract them.',
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
      guidance: 'MCP config files are shared across workspaces and often committed to repos. Credentials there are exposed to every tool and extension that reads the config.',
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
      guidance: 'An MCP server with root or home directory access can read SSH keys, cloud credentials, and any file on the system. Scope access to the project directory only.',
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
      guidance: 'Private key files (.pem, .key) in a project directory are easily committed to git. Once pushed, the keys are compromised and must be rotated.',
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
        ? 'package.json contains hardcoded secrets'
        : 'No secrets found in package.json',
      fixable: false,
      fix: hasSecretsInPackageJson ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'package.json is always committed to git and published to npm. Secrets there are visible to anyone who installs or forks your package.',
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
        ? 'JWT secret hardcoded in config'
        : 'No hardcoded JWT secrets found',
      fixable: false,
      fix: hasJwtSecret ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'A hardcoded JWT secret lets anyone who reads the config forge valid authentication tokens and impersonate any user.',
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
      guidance: 'Executable config files can be run as scripts. An attacker who modifies a config file with execute permission can trick the system into running arbitrary code.',
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
      guidance: 'Group-writable sensitive files allow other users in the same group to modify credentials or inject malicious configuration values.',
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
      guidance: 'Development mode typically disables security features like CSRF protection, strict CORS, and error sanitization, leaving the application exposed in production.',
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
      guidance: 'Debug and verbose logging flags can leak internal state, database queries, and credential values into log files or console output.',
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
      guidance: 'Verbose error messages expose stack traces, file paths, and internal logic to attackers, making it easier to find exploitable weaknesses.',
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
      guidance: 'Without environment validation, missing or malformed variables cause silent failures. A missing DB_HOST might fall back to an insecure default rather than failing fast.',
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
      guidance: 'Unstructured console.log output is hard to filter, search, or redact. Structured logging makes it possible to automatically mask sensitive fields and detect anomalies.',
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
      guidance: 'Passwords, API keys, and tokens logged to console or files persist in log aggregators and crash reports, where they can be harvested by anyone with log access.',
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
      guidance: 'World-readable log files let any local user read application logs, which often contain request details, internal errors, and sometimes credentials.',
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
      guidance: 'Without audit logging, there is no record of who accessed what or when. Incident response becomes guesswork without a trail of security-relevant events.',
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
      guidance: 'Without a lock file, npm install can resolve to different package versions on different machines, including versions with known vulnerabilities or supply-chain backdoors.',
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
      guidance: 'These packages have confirmed supply-chain compromises (e.g., event-stream injected a cryptocurrency-stealing payload). Remove or replace them immediately.',
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
      guidance: 'Wildcard (*) or "latest" versions accept any future release, including ones compromised by supply-chain attacks. Pin versions and use a lock file.',
    });

    // DEP-004: Check for npm scripts security
    let hasDangerousScripts = false;
    const dangerousScriptRegexes = [
      /curl\b.*\|\s*sh/i,        // curl ... | sh (with anything between)
      /curl\b.*\|\s*bash/i,      // curl ... | bash
      /wget\b.*\|\s*sh/i,        // wget ... | sh
      /wget\b.*\|\s*bash/i,      // wget ... | bash
      /\beval\s*\(/,             // eval(
      /\$\(curl\b/,             // $(curl
      /\$\(wget\b/,             // $(wget
    ];
    const pkgJsonPath = path.join(targetDir, 'package.json');
    try {
      const pkgJson = await fs.readFile(pkgJsonPath, 'utf-8');
      const pkg = JSON.parse(pkgJson);
      if (pkg.scripts) {
        for (const [, script] of Object.entries(pkg.scripts)) {
          if (typeof script === 'string') {
            for (const pattern of dangerousScriptRegexes) {
              if (pattern.test(script)) {
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
      file: hasDangerousScripts ? 'package.json' : undefined,
      message: hasDangerousScripts
        ? 'Dangerous patterns in npm scripts (curl|sh, eval) - review carefully'
        : 'npm scripts appear safe',
      fixable: false,
      fix: hasDangerousScripts
        ? 'Remove the curl|sh or wget|sh pattern from package.json scripts. Replace with a pinned package install: npm install --save-exact <package>  or vendor the script with a pinned checksum.'
        : undefined,
      guidance: 'Scripts that pipe curl/wget to sh execute arbitrary remote code during npm install. An attacker who compromises the URL controls your build environment.',
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
      guidance: 'Without authentication, any network-reachable client can access your API endpoints, including reading data, triggering actions, and modifying state.',
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
      guidance: 'Without rate limiting, attackers can brute-force credentials, scrape data, or exhaust resources with automated requests at no cost.',
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
      guidance: 'Sessions without secure and httpOnly flags are vulnerable to theft via XSS attacks or network sniffing, allowing attackers to hijack authenticated sessions.',
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
      guidance: 'Without explicit CORS configuration, browsers may block legitimate cross-origin requests or, worse, a permissive default may allow malicious sites to make authenticated requests to your API.',
    });

    return findings;
  }

  private async checkProcessSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // PROC-001: Check for Dockerfile security
    // Search common Dockerfile locations
    let hasSecureDockerfile = true;
    let dockerfilePath: string | undefined;
    const dockerfileCandidates = [
      'Dockerfile',
      'Dockerfile.prod',
      'Dockerfile.production',
      'Dockerfile.dev',
      'docker/Dockerfile',
    ];
    for (const candidate of dockerfileCandidates) {
      const candidatePath = path.join(targetDir, candidate);
      try {
        const dockerfile = await fs.readFile(candidatePath, 'utf-8');
        dockerfilePath = candidatePath;
        if (dockerfile.includes('USER root') || !dockerfile.includes('USER ')) {
          hasSecureDockerfile = false;
        }
        break; // Use the first Dockerfile found
      } catch {
        // File not found, try next candidate
      }
    }

    findings.push({
      checkId: 'PROC-001',
      name: 'Container User',
      description: 'Dockerfile runs as root or has no USER directive',
      category: 'process',
      severity: 'high',
      passed: hasSecureDockerfile,
      file: !hasSecureDockerfile && dockerfilePath ? path.relative(targetDir, dockerfilePath) : undefined,
      message: hasSecureDockerfile
        ? 'Container runs as non-root user or no Dockerfile present'
        : 'Dockerfile runs as root - add USER directive for non-root user',
      fixable: false,
      guidance: 'A container running as root means any exploit that escapes the application gets full control of the container and potentially the host system.',
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
      guidance: 'Missing security headers (CSP, X-Frame-Options, HSTS) leave your app vulnerable to clickjacking, XSS, and protocol downgrade attacks.',
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
      guidance: 'Without input validation, attackers can inject SQL, scripts, or malformed data that corrupts state, steals data, or crashes the application.',
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
      guidance: 'Unhandled errors can crash the process, leak stack traces with internal paths and variable names, and create denial-of-service conditions.',
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
      guidance: 'Without deny rules, Claude Code can execute any tool or command. Deny rules act as a blocklist to prevent dangerous operations like rm -rf or credential access.',
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
      guidance: 'Persistent memory can retain API keys, internal URLs, or confidential instructions across sessions. An attacker who gains access to the memory store can extract this data.',
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
      guidance: 'CLAUDE.md is typically committed to version control. Sensitive instructions there can be extracted via prompt injection or by anyone with repo access.',
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
      guidance: 'Without tool timeouts, a stuck or malicious tool call can hang indefinitely, consuming resources and blocking the agent from responding.',
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
      guidance: 'Without request timeouts, a hung or malicious MCP server can block the agent indefinitely, causing denial-of-service and preventing other tools from executing.',
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
      guidance: 'Without retry limits, a failing MCP server can trigger infinite retry loops that waste API credits, saturate network connections, and stall the agent.',
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
      guidance: 'MCP servers running over network (SSE/HTTP) without authentication let any network-adjacent attacker connect and issue tool calls.',
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
      guidance: 'Tools named shell, exec, or eval typically provide arbitrary code execution. A prompt injection that invokes these tools can fully compromise the host system.',
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
      guidance: 'Logging MCP requests and responses creates an audit trail for detecting misuse. Without it, malicious tool calls leave no trace for incident response.',
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
      guidance: 'Without TLS, all traffic including API keys, tokens, and user data is transmitted in plaintext. Anyone on the network can intercept and read it.',
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
      guidance: 'Debug and admin endpoints expose internal state, configuration, and metrics. Attackers use these to map your infrastructure and find weaknesses.',
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
      guidance: 'Unauthenticated WebSocket connections let any client send commands to your backend. Unlike HTTP, WebSockets maintain persistent connections that bypass traditional request-based security.',
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
      guidance: 'HTTP proxies without SSRF protections allow attackers to reach internal services, cloud metadata endpoints, and private networks through your server.',
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
      guidance: 'Without API versioning, breaking changes affect all clients immediately. Versioning enables safe deprecation and prevents accidental security regressions.',
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
      guidance: 'Undocumented APIs are harder to use correctly and easier to misuse. Clear documentation reduces the chance of insecure integrations by consumers.',
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
      guidance: 'API keys in URLs are logged by browsers, proxies, and web servers. They appear in referrer headers and browser history, making them easy to steal.',
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
      guidance: 'Missing security headers like X-Frame-Options and CSP leave your API responses vulnerable to clickjacking, MIME-sniffing, and cross-site scripting attacks.',
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
      guidance: 'Without a secret manager, credentials end up in .env files, config files, or source code where they can be leaked through version control or log files.',
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
      guidance: 'Without encryption, sensitive data like passwords and tokens are stored in plaintext. A database breach or file leak exposes everything immediately.',
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
      guidance: 'Without key rotation, a single compromised key grants permanent access. Regular rotation limits the window of exposure when a key is leaked.',
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
        ? 'Hardcoded connection strings detected'
        : 'No hardcoded connection strings found',
      fixable: false,
      fix: hasHardcodedConnStr ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'Hardcoded connection strings contain database hostnames, ports, and credentials. Anyone with code access can connect directly to your database.',
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
      guidance: 'Unrestricted file uploads let attackers send malicious executables, web shells, or oversized files that can compromise the server or exhaust disk space.',
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
      guidance: 'Raw database queries built with string concatenation let attackers inject SQL or NoSQL commands that can read, modify, or delete all data in the database.',
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
      guidance: 'Without XSS protection, user-supplied content rendered in the browser can execute arbitrary JavaScript, stealing session tokens and user data.',
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
      guidance: 'Path traversal (../) in file paths lets attackers read sensitive files like /etc/passwd or .env by escaping the intended directory.',
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
      guidance: 'Without clear boundary markers, attackers can inject instructions that blend with the system prompt, making it impossible for the model to distinguish trusted from untrusted content.',
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
      guidance: 'System prompts without injection defenses can be overridden by user inputs that say "ignore previous instructions", bypassing all safety rules.',
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
      guidance: 'Without output confidentiality rules, the agent may freely reveal system prompts, internal tool names, API keys, or other sensitive context when asked.',
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
      guidance: 'Without a clear role definition, attackers can use "you are now a hacker assistant" style prompts to override the agent identity and bypass safety constraints.',
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
      guidance: 'Without schema validation, any malformed or malicious input reaches your application logic. This is the root cause of injection, overflow, and type confusion attacks.',
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
      guidance: 'Unescaped user content rendered in HTML lets attackers inject scripts that steal cookies, hijack sessions, and impersonate users.',
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
      guidance: 'SQL injection via string concatenation lets attackers read, modify, or delete any data in your database. Parameterized queries prevent this entirely.',
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
      guidance: 'Using exec() with user-controlled input lets attackers inject shell metacharacters (;, |, $()) to run arbitrary commands on the host system.',
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
      guidance: 'Without rate limiting, attackers can make unlimited API calls, exhausting your quota and running up costs. It also enables brute-force and credential stuffing attacks.',
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
      guidance: 'Without exponential backoff, retries hammer external services at full speed during outages, worsening the problem and potentially getting your API key banned.',
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
      guidance: 'Without timeouts, a slow or unresponsive external service can cause your application to hang indefinitely, tying up connections and eventually crashing.',
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
      guidance: 'Without concurrency limits, a burst of requests can spawn unbounded parallel operations that exhaust memory, file descriptors, and CPU, crashing the service.',
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
      guidance: 'Session cookies without secure flags can be stolen via XSS (missing httpOnly), sent over plain HTTP (missing secure), or exploited in cross-site attacks (missing sameSite).',
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
      guidance: 'Sessions without expiry remain valid indefinitely. A stolen session token grants permanent access until the server is restarted or the token is manually revoked.',
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
      guidance: 'Without CSRF protection, a malicious website can trick authenticated users into performing unwanted actions (transfers, password changes, data deletion) by forging requests from their browser.',
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
      guidance: 'Tokens stored in plaintext files or localStorage can be stolen by any process with file access or XSS attack, allowing full account takeover without credentials.',
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
      guidance: 'Without encryption at rest, anyone with disk access (stolen laptop, compromised server, backup leak) can read sensitive data including credentials and user information.',
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
      guidance: 'Passwords hashed with fast algorithms (MD5, SHA1) can be cracked in bulk using rainbow tables or GPU brute-force. Bcrypt, argon2, and scrypt are deliberately slow to resist this.',
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
      guidance: 'MD5 and SHA1 have known collision attacks, and DES has a 56-bit key easily brute-forced with modern hardware. Data protected by these algorithms should be considered unprotected.',
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
      guidance: 'Without TLS, all network traffic including credentials, tokens, and sensitive data is transmitted in plaintext and can be intercepted by anyone on the network path.',
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
      guidance: 'Missing audit logs mean you cannot detect or investigate security incidents after they occur. Attackers operate undetected and forensic analysis becomes impossible.',
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
      guidance: 'Without log rotation, logs grow until they fill the disk, causing service outages. Attackers can also exploit this to trigger denial-of-service by generating excessive log entries.',
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
      guidance: 'Without error tracking, security-related failures (auth errors, injection attempts, rate limit hits) go unnoticed in production, giving attackers time to refine their approach.',
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
      guidance: 'Unsanitized logs containing passwords, tokens, or PII become a secondary breach vector. Log aggregation services, backups, and support teams all gain access to sensitive data.',
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
      guidance: 'Without container isolation, a compromised application has direct access to the host filesystem, network, and other processes. Containers limit the blast radius of a breach.',
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
      guidance: 'Containers running as root can escape container isolation more easily. A container breakout as root grants full control of the host system.',
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
      guidance: 'Without resource limits, a single compromised or buggy container can consume all host CPU and memory, causing denial-of-service for every other service on the machine.',
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
      guidance: 'A writable filesystem allows attackers to drop malware, modify binaries, or plant persistence mechanisms inside the container. Read-only filesystems prevent post-exploitation tampering.',
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
      guidance: 'Without an explicit tool whitelist, MCP servers expose all available tools to the AI agent. A prompt injection attack can invoke any tool, including destructive ones.',
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
      guidance: 'Without token limits and timeouts, a runaway or malicious tool call can consume unlimited API credits and block the agent indefinitely.',
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
      guidance: 'Shell and exec tools give the AI agent arbitrary command execution on the host. A prompt injection can leverage these to exfiltrate data, install malware, or pivot to other systems.',
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
      guidance: 'Without confirmation gates, the AI agent can execute destructive operations (file deletion, database drops, deployments) in a single step with no human checkpoint.',
    });

    return findings;
  }

  calculateScore(findings: SecurityFinding[]): {
    score: number;
    maxScore: number;
  } {
    return calculateSecurityScore(findings);
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

    // Backup each file that exists (static list + web directory scan)
    const filesToBackup = [...HardeningScanner.BACKUP_FILES];

    // Also discover files in web-served directories that --fix may modify
    const webDirs = ['public', 'static', 'dist', 'build', 'out', 'www', '_site'];
    const webExts = ['.html', '.htm', '.js', '.jsx', '.tsx', '.css', '.py', '.md'];
    for (const webDir of webDirs) {
      const webDirPath = path.join(targetDir, webDir);
      try {
        const entries = await fs.readdir(webDirPath, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isFile() && webExts.some(ext => entry.name.endsWith(ext))) {
            filesToBackup.push(path.join(webDir, entry.name));
          }
        }
      } catch { /* dir doesn't exist */ }
    }

    for (const file of filesToBackup) {
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
      throw new Error('No backup found. Run hackmyagent secure --fix <dir> first to create a backup.');
    }

    // Find the most recent backup
    const backups = await fs.readdir(backupBaseDir);
    const sortedBackups = backups
      .filter((b) => !b.startsWith('.'))
      .sort()
      .reverse();

    if (sortedBackups.length === 0) {
      throw new Error('No backup found. Run hackmyagent secure --fix <dir> first to create a backup.');
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
   * OpenClaw skill security checks (SKILL-001 to SKILL-024)
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
        content.includes('-----BEGIN SIGNATURE-----') ||
        content.includes('<!-- opena2a-guard hash=');

      let skill001Fixed = false;
      if (!hasSignature && autoFix) {
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        const signedDate = new Date().toISOString();
        const signatureBlock = `\n<!-- opena2a-guard hash="sha256:${hash}" signed="${signedDate}" -->`;
        content = content + signatureBlock;
        await fs.writeFile(skillFile, content);
        skill001Fixed = true;
      }

      findings.push({
        checkId: 'SKILL-001',
        name: 'Unsigned Skill',
        description: 'Skill file lacks cryptographic signature for authenticity verification',
        category: 'skill',
        severity: 'medium',
        passed: hasSignature || skill001Fixed,
        message: hasSignature
          ? 'Skill has cryptographic signature'
          : skill001Fixed
            ? 'Skill was unsigned - signature added'
            : 'Skill is unsigned - cannot verify authenticity or integrity',
        file: relativePath,
        fixable: true,
        fixed: skill001Fixed,
        fixMessage: skill001Fixed ? 'Added SHA-256 signature block to skill file' : undefined,
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Unsigned skills cannot be verified for authenticity or integrity. Sign with a cryptographic identity to enable tamper detection.',
      });

      // SKILL-002: Remote Fetch Pattern
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_REMOTE_FETCH_PATTERNS) {
          // Reset regex lastIndex for global patterns
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            const section = classifySkillSection(content, i);
            if (isLikelyFalsePositive('SKILL-002', line, section, content)) {
              continue;
            }
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
              fix: 'Remove the curl|sh or wget|sh pattern from this file',
              guidance: 'Remote code execution patterns download and execute arbitrary code. Replace with a pinned dependency or vendored script with checksum verification.',
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
            fix: 'Move scheduled task configuration to a separate heartbeat config file',
            guidance: 'Skills that install heartbeats or cron jobs gain persistent execution beyond the user session. Heartbeats should be configured separately with restricted permissions.',
          });
        }
      }

      // SKILL-004: Filesystem Write Outside Sandbox
      const filesystemWildcardPattern = /filesystem:\s*\*|filesystem:\s*~\/|filesystem:\s*\//gi;
      let skill004FileModified = false;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        filesystemWildcardPattern.lastIndex = 0;
        if (filesystemWildcardPattern.test(line)) {
          let fixApplied = false;
          if (autoFix) {
            const originalLine = lines[i];
            lines[i] = lines[i].replace(/filesystem:\s*\*/gi, 'filesystem:./');
            lines[i] = lines[i].replace(/filesystem:\s*~\//gi, 'filesystem:./data/');
            if (lines[i] !== originalLine) {
              fixApplied = true;
              skill004FileModified = true;
            }
          }

          findings.push({
            checkId: 'SKILL-004',
            name: 'Filesystem Write Outside Sandbox',
            description: 'Skill requests broad filesystem access outside sandbox',
            category: 'skill',
            severity: 'critical',
            passed: fixApplied,
            message: fixApplied
              ? `Broad filesystem access restricted: "${lines[i].trim()}"`
              : `Broad filesystem access requested: "${line.trim()}"`,
            file: relativePath,
            line: i + 1,
            fixable: true,
            fixed: fixApplied,
            fixMessage: fixApplied ? 'Restricted filesystem access to sandbox scope' : undefined,
            fix: 'hackmyagent secure --fix',
            guidance: 'Broad filesystem access (filesystem:* or filesystem:~/) lets skills read/write anywhere. Restrict to specific directories (e.g., filesystem:./data/*).',
          });
        }
      }
      if (skill004FileModified) {
        content = lines.join('\n');
        await fs.writeFile(skillFile, content);
      }

      // SKILL-005: Credential File Access
      // Only flag as CRITICAL inside frontmatter (capabilities section).
      // Body text often describes credential handling in documentation,
      // which is informational, not an actual access pattern.
      let inSkill005Frontmatter = false;
      let skill005FrontmatterDelimiters = 0;
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (trimmed === '---') {
          skill005FrontmatterDelimiters++;
          inSkill005Frontmatter = skill005FrontmatterDelimiters === 1;
          if (skill005FrontmatterDelimiters >= 2) inSkill005Frontmatter = false;
          continue;
        }
        const line = lines[i];
        for (const pattern of SKILL_CREDENTIAL_ACCESS_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            // Frontmatter = actual capability declaration (CRITICAL)
            // Body = still suspicious but lower severity (MEDIUM)
            const severity = inSkill005Frontmatter ? 'critical' : 'medium';
            findings.push({
              checkId: 'SKILL-005',
              name: 'Credential File Access',
              description: inSkill005Frontmatter
                ? 'Skill declares access to credential or sensitive configuration files'
                : 'Skill body mentions credential file patterns',
              category: 'skill',
              severity,
              passed: false,
              message: `Credential file access pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove credential file access patterns from this skill',
              guidance: 'Skills accessing ~/.ssh, ~/.aws, wallets, or .env files can exfiltrate credentials. Use npx secretless-ai init to protect credentials from AI tool context.',
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
              fix: 'Remove the exfiltration endpoint from this skill',
              guidance: 'Data exfiltration patterns (webhook.site, requestbin, ngrok, suspicious POST) send local data to external servers. Remove or replace with audited, allow-listed endpoints.',
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
            const section = classifySkillSection(content, i);
            if (isLikelyFalsePositive('SKILL-007', line, section, content)) {
              continue;
            }
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
              fix: 'Remove the copy/paste instruction block from this skill',
              guidance: 'ClickFix social engineering tricks users into copying and pasting malicious commands. This technique was used extensively in the ClawHavoc campaign.',
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
              fix: 'Remove the reverse shell pattern from this skill',
              guidance: 'Reverse shell patterns (netcat, bash -i, /dev/tcp) establish remote command execution. This is a strong indicator of malicious intent.',
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
            fix: `hackmyagent check ${relativePath}`,
            guidance: 'Typosquatting uses names similar to popular skills to trick users into installing malicious versions. Verify the skill source and rename if unintentional.',
          });
          break; // One typosquatting finding per skill file
        }
      }

      // SKILL-010: Env File Exfiltration (context-aware)
      //
      // Must match an ACTUAL env-access action, not just the substring ".env"
      // or "environment". A documentation section that lists patterns like
      // ".env, .pem, .key" is not env exfiltration. Real signals:
      //   - Direct env-var access syntax (process.env, os.environ[, getenv())
      //   - Destructuring from process.env (covers `const {KEY} = process.env`)
      //   - Runtime-specific env APIs (Deno.env.get, Bun.env.KEY)
      //   - dotenv loaders (dotenv.config(), load_dotenv())
      //   - Shell dumps of the whole env (`env | curl ...`, `printenv | nc`)
      //   - Shell exfil over an .env file (cat/curl/scp/... .env)
      //   - File-read API with an .env argument (readFile('.env'), Read('.env'))
      //   - curl --data-binary @.env (send .env contents as POST body)
      const envFilePattern = /process\.env\b|\bos\.environb?\b|\bgetenv\s*\(|\bDeno\.env\b|\bBun\.env\b|\bdotenv(?:\.config|_values|\.parse)\s*\(|\bload_dotenv\s*\(|\brequire\s*\(\s*['"`]dotenv(?:\/config)?['"`]\s*\)|\bimport\s+[^;]*['"`]dotenv(?:\/config)?['"`]|\b(?:cat|head|tail|curl|wget|scp|rsync|tar|zip|xxd|base64)\s+[^|\n]*\.env\b|\b(?:env|printenv)\s*[|>]|(?:read|readFile|readFileSync|open)\s*\(\s*['"`][^'"`]*\.env|\bRead\s*\(\s*['"`][^'"`]*\.env|@\.env\b|\bsource\s+\.?env\b/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        envFilePattern.lastIndex = 0;
        if (envFilePattern.test(line)) {
          const section = classifySkillSection(content, i);
          if (isLikelyFalsePositive('SKILL-010', line, section, content)) {
            continue;
          }
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
            fix: 'npx secretless-ai init',
            guidance: 'Skills accessing .env files or process.env can exfiltrate API keys and secrets. Use Secretless AI to block credential access from AI tool context.',
          });
        }
      }

      // SKILL-011: Browser Data Access (context-aware)
      const browserDataPattern = /chrome|firefox|cookies|localStorage|sessionStorage|browser.*data|chromium|safari.*cookies/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        browserDataPattern.lastIndex = 0;
        if (browserDataPattern.test(line)) {
          const section = classifySkillSection(content, i);
          if (isLikelyFalsePositive('SKILL-011', line, section, content)) {
            continue;
          }
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
            fix: 'Remove browser data access patterns from this skill',
            guidance: 'Skills accessing browser data (cookies, localStorage, sessionStorage) can steal session tokens and authentication state.',
          });
        }
      }

      // SKILL-012: Crypto Wallet Access (context-aware)
      const cryptoWalletPattern = /wallet|solana|phantom|metamask|ledger|seed\s*phrase|mnemonic|\.sol\b|\.eth\b|private\s*key/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        cryptoWalletPattern.lastIndex = 0;
        if (cryptoWalletPattern.test(line)) {
          const section = classifySkillSection(content, i);
          if (isLikelyFalsePositive('SKILL-012', line, section, content)) {
            continue;
          }
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
            fix: 'Remove crypto wallet access patterns from this skill',
            guidance: 'Skills accessing wallets, seed phrases, or private keys can drain cryptocurrency funds. No legitimate skill needs this access.',
          });
        }
      }

      // SKILL-018: Undeclared Capability Validation
      const declaredCaps = parseSkillDeclaredCaps(content);
      const inferredCaps = inferActualCapabilities(content);
      const capFindings = validateCapabilities(declaredCaps, inferredCaps, relativePath);
      findings.push(...capFindings);

      // SKILL-019: Stale Skill Signature
      const signatureMatch = content.match(
        /<!-- opena2a-guard hash="sha256:([a-f0-9]+)" signed="([^"]+)"(?: expires_at="([^"]+)")? -->/
      );
      if (signatureMatch) {
        const storedHash = signatureMatch[1];
        const signatureBlock = signatureMatch[0];
        // Compute hash of content excluding the signature block
        const contentWithoutSig = content.replace(signatureBlock, '').replace(/\n$/, '');
        const computedHash = crypto.createHash('sha256').update(contentWithoutSig).digest('hex');

        if (storedHash !== computedHash) {
          let skill019Fixed = false;
          if (autoFix) {
            const newHash = crypto.createHash('sha256').update(contentWithoutSig).digest('hex');
            const newDate = new Date().toISOString();
            const expiresAt = signatureMatch[3]
              ? ` expires_at="${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()}"`
              : '';
            const newSigBlock = `<!-- opena2a-guard hash="sha256:${newHash}" signed="${newDate}"${expiresAt} -->`;
            content = content.replace(signatureBlock, newSigBlock);
            await fs.writeFile(skillFile, content);
            skill019Fixed = true;
          }

          findings.push({
            checkId: 'SKILL-019',
            name: 'Stale Skill Signature',
            description: 'Skill content has changed since it was signed - signature hash mismatch',
            category: 'skill',
            severity: 'medium',
            passed: skill019Fixed,
            message: skill019Fixed
              ? 'Stale signature detected and re-signed'
              : 'Signature hash does not match current content - skill may have been tampered with',
            file: relativePath,
            fixable: true,
            fixed: skill019Fixed,
            fixMessage: skill019Fixed ? 'Re-computed hash and updated signature block' : undefined,
            fix: 'hackmyagent secure --fix',
            guidance: 'The signature hash no longer matches the file content. This could indicate tampering or a legitimate edit that was not re-signed.',
          });
        }

        // HEARTBEAT-007: Expired Heartbeat (check expires_at in signature block)
        if (signatureMatch[3]) {
          const expiresAt = new Date(signatureMatch[3]);
          const now = new Date();
          if (expiresAt < now) {
            let hb007Fixed = false;
            if (autoFix) {
              const contentWithoutSig = content.replace(signatureMatch[0], '').replace(/\n$/, '');
              const newHash = crypto.createHash('sha256').update(contentWithoutSig).digest('hex');
              const newDate = new Date().toISOString();
              const newExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
              const newSigBlock = `<!-- opena2a-guard hash="sha256:${newHash}" signed="${newDate}" expires_at="${newExpiry}" -->`;
              content = content.replace(signatureMatch[0], newSigBlock);
              await fs.writeFile(skillFile, content);
              hb007Fixed = true;
            }

            findings.push({
              checkId: 'HEARTBEAT-007',
              name: 'Expired Heartbeat',
              description: 'Skill signature has expired and needs renewal',
              category: 'skill',
              severity: 'high',
              passed: hb007Fixed,
              message: hb007Fixed
                ? 'Expired signature renewed with 7-day validity'
                : `Skill signature expired at ${signatureMatch[3]}`,
              file: relativePath,
              fixable: true,
              fixed: hb007Fixed,
              fixMessage: hb007Fixed ? 'Updated expiry to 7 days from now and re-signed' : undefined,
              fix: 'hackmyagent secure --fix',
              guidance: 'Expired signatures mean the skill has not been re-verified since its expiry date. Re-signing renews the validity period and re-verifies content integrity.',
            });
          }
        }
      }

      // SKILL-020: Missing/invalid frontmatter
      const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
      if (!fmMatch) {
        findings.push({
          checkId: 'SKILL-020',
          name: 'Missing YAML Frontmatter',
          description: 'Skill file lacks required YAML frontmatter for capability declaration',
          category: 'skill',
          severity: 'high',
          passed: false,
          message: `${relativePath}: Skill file lacks required YAML frontmatter (---). Add frontmatter with name, version, and capabilities fields.`,
          file: relativePath,
          fixable: true,
          fix: 'Add YAML frontmatter block with name, version, and capabilities fields',
          guidance: 'Skills without frontmatter cannot declare their capabilities, making permission validation impossible. Add a --- delimited YAML block at the top of the file.',
        });
      } else {
        const fmRaw = fmMatch[1];
        const requiredFields = ['name', 'version', 'capabilities'];
        const missingFields = requiredFields.filter(f => !new RegExp(`^${f}:`, 'm').test(fmRaw));
        if (missingFields.length > 0) {
          findings.push({
            checkId: 'SKILL-020',
            name: 'Incomplete Frontmatter',
            description: 'Skill frontmatter is missing required fields',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `${relativePath}: Missing required frontmatter fields: ${missingFields.join(', ')}. These are needed for capability declaration and version tracking.`,
            file: relativePath,
            fixable: true,
            fix: `Add missing fields to frontmatter: ${missingFields.join(', ')}`,
            guidance: 'Incomplete frontmatter prevents proper capability validation. Every skill should declare name, version, and capabilities.',
          });
        } else {
          findings.push({
            checkId: 'SKILL-020',
            name: 'Valid Frontmatter',
            description: 'Skill file has valid YAML frontmatter with required fields',
            category: 'skill',
            severity: 'high',
            passed: true,
            message: 'Skill has valid frontmatter with name, version, and capabilities',
            file: relativePath,
            fixable: false,
            fix: 'No action needed',
            guidance: 'Skill frontmatter is properly configured.',
          });
        }
      }

      // SKILL-021: Overprivileged permissions (dangerous capability combinations)
      const dangerousCombos: Array<{ combo: [string, string]; reason: string }> = [
        {
          combo: ['filesystem:*', 'network:outbound'],
          reason: 'filesystem:* + network:outbound enables data exfiltration',
        },
        {
          combo: ['credential:read', 'network:outbound'],
          reason: 'credential:read + network:outbound enables credential exfiltration',
        },
      ];
      const capPatterns = content.match(/(?:filesystem|network|credential|tool):[a-z*]+/g) || [];
      const allCaps = [...new Set(capPatterns)];
      // Also include capabilities from frontmatter if parsed
      const declaredCapsForPriv = parseSkillDeclaredCaps(content);
      for (const dc of declaredCapsForPriv.capabilities) {
        if (!allCaps.includes(dc)) allCaps.push(dc);
      }

      for (const { combo, reason } of dangerousCombos) {
        const matchCap = (actual: string, pattern: string): boolean => {
          if (actual === pattern) return true;
          if (pattern.endsWith(':*')) return actual.startsWith(pattern.slice(0, -1));
          if (actual.endsWith(':*')) return pattern.startsWith(actual.slice(0, -1));
          return false;
        };
        const hasFirst = allCaps.some(c => matchCap(c, combo[0]));
        const hasSecond = allCaps.some(c => matchCap(c, combo[1]));

        if (hasFirst && hasSecond) {
          findings.push({
            checkId: 'SKILL-021',
            name: 'Overprivileged Permissions',
            description: 'Skill has dangerous capability combination that enables exfiltration',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `${relativePath}: ${reason}. Restrict filesystem access to specific paths or remove outbound network access.`,
            file: relativePath,
            fixable: false,
            fix: 'Restrict capabilities to minimum required permissions',
            guidance: 'Dangerous capability combinations can enable data or credential exfiltration. Follow the principle of least privilege.',
          });
        }
      }

      // SKILL-022: Environment variable exfiltration
      const envAccessPatterns = [
        /process\.env/,
        /os\.environ/,
        /\$ENV\{/,
        /System\.getenv/,
        /printenv/,
        /\$\(env\)/,
        /\$\(printenv/,
        /\$HOME\b/,
        /\$\{[A-Z_]+\}/,
      ];
      const outboundPatterns = [
        /network:outbound/,
        /fetch\s*\(/,
        /https?:\/\//,
        /XMLHttpRequest/,
        /\.send\s*\(/,
        /curl\s/,
        /wget\s/,
      ];
      const hasEnvAccess = envAccessPatterns.some(p => p.test(content));
      const hasOutbound = outboundPatterns.some(p => p.test(content));

      if (hasEnvAccess && hasOutbound) {
        findings.push({
          checkId: 'SKILL-022',
          name: 'Environment Variable Exfiltration Risk',
          description: 'Skill accesses environment variables and has outbound network capability',
          category: 'skill',
          severity: 'critical',
          passed: false,
          message: `${relativePath}: Skill accesses environment variables AND has outbound network capability. This combination can exfiltrate secrets via network requests.`,
          file: relativePath,
          fixable: false,
          fix: 'Remove outbound network access or environment variable reads',
          guidance: 'Skills that read environment variables and send data externally can exfiltrate API keys, tokens, and other secrets stored in environment variables.',
        });
      }

      // SKILL-023: Obfuscated code patterns
      const obfuscationPatterns = [
        { pattern: /atob\s*\(/, label: 'atob() base64 decode' },
        { pattern: /Buffer\.from\s*\(/, label: 'Buffer.from() decode' },
        { pattern: /eval\s*\(/, label: 'eval() dynamic execution' },
        { pattern: /String\.fromCharCode/, label: 'String.fromCharCode obfuscation' },
        { pattern: /\\x[0-9a-fA-F]{2}/, label: 'hex-encoded string' },
        { pattern: /(?:atob|Buffer\.from)\s*\([^)]+\)[\s\S]*?eval\s*\(/, label: 'base64+eval combo' },
        { pattern: /base64\s+-d/, label: 'shell base64 decode' },
        { pattern: /eval\s+\$\(/, label: 'shell eval $(...)' },
        { pattern: /\becho\s+['"][A-Za-z0-9+/=]{20,}['"]\s*\|\s*base64/, label: 'echo+base64 pipe' },
        { pattern: /new\s+Function\s*\(/, label: 'new Function() dynamic execution' },
      ];

      for (const { pattern, label } of obfuscationPatterns) {
        if (pattern.test(content)) {
          findings.push({
            checkId: 'SKILL-023',
            name: 'Obfuscated Code Pattern',
            description: 'Skill contains obfuscated code that may hide malicious behavior',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `${relativePath}: Detected ${label}. Obfuscated code in skills can hide malicious behavior and should be reviewed.`,
            file: relativePath,
            fixable: false,
            fix: 'Replace obfuscated code with readable equivalent',
            guidance: 'Obfuscated code (base64 decode, eval, hex-encoded strings) in skills is a strong indicator of hidden malicious behavior. Review and replace with transparent code.',
          });
          break; // One finding per file for obfuscation
        }
      }

      // SKILL-024: Unbounded tool chaining
      const hasToolChain = allCaps.some(c => c.includes('tool:chain'));
      if (hasToolChain) {
        const hasFm = !!fmMatch;
        const fmContent = hasFm ? fmMatch[1] : '';
        const hasMaxIterations = hasFm && (
          /maxIterations/i.test(fmContent) ||
          /iterationLimit/i.test(fmContent)
        );

        if (!hasMaxIterations) {
          findings.push({
            checkId: 'SKILL-024',
            name: 'Unbounded Tool Chaining',
            description: 'Skill declares tool:chain capability without iteration limits',
            category: 'skill',
            severity: 'medium',
            passed: false,
            message: `${relativePath}: Skill declares tool:chain capability without maxIterations or iterationLimit. Unbounded chaining can lead to infinite loops or resource exhaustion.`,
            file: relativePath,
            fixable: true,
            fix: 'Add maxIterations or iterationLimit to skill frontmatter',
            guidance: 'Tool chaining without iteration limits can cause infinite loops, resource exhaustion, or runaway costs. Set a reasonable maxIterations value in frontmatter.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
            guidance: 'Heartbeats that contact external URLs without verification can be redirected to malicious endpoints. Pin the expected hash to detect tampering.',
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
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Without hash pinning, heartbeat content can be modified without detection. Pinning creates a cryptographic fingerprint to verify integrity on each execution.',
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
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Unsigned heartbeats cannot prove who created them or whether they have been modified. Cryptographic signatures enable authenticity and integrity verification.',
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
              guidance: 'Wildcard capabilities (shell:*, filesystem:*, network:*) give heartbeats unrestricted access. A compromised heartbeat with these permissions can execute arbitrary commands, read any file, or exfiltrate data.',
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
              guidance: 'High-frequency heartbeats consume CPU, memory, and network bandwidth. Intervals under 5 minutes can cause resource exhaustion and may mask malicious polling behavior.',
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
        guidance: 'Unrestricted heartbeats run 24/7 including off-hours when no one monitors them. Time-of-day limits reduce the window for undetected malicious activity.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Binding to 0.0.0.0 exposes the gateway to all network interfaces. Use 127.0.0.1 for local-only access unless remote access is explicitly needed with proper authentication.',
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
        fix: 'Add security.websocketOrigins: ["http://localhost:3000"] to the gateway config',
        guidance: 'Without origin validation, any website can connect to the gateway via WebSocket (GHSA-g8p2). This enables cross-origin command execution attacks.',
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
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Plaintext tokens in config files are exposed to anyone with repo access. Use environment variable references so credentials stay outside version control.',
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
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Without approval confirmations, commands execute immediately without user review. This removes the last line of defense against malicious or accidental destructive operations.',
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
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Without sandbox isolation, executed code has full system access including filesystem, network, and process control. Sandbox mode limits the blast radius of malicious or buggy code.',
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
          fix: 'Disable docker.privileged and remove sensitive mounts (/var/run/docker.sock, /etc/passwd, /:/) from the config',
          guidance: 'Privileged mode and sensitive host mounts allow container escape -- the agent can access the host system, other containers, and all their data.',
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
          guidance: 'An open DM policy with wildcard allows any entity to send messages to the agent. Attackers can use this to inject commands or exfiltrate data via conversation.',
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
          guidance: 'Tailscale Funnel exposes the agent to the public internet, bypassing Tailscale\'s private network protection. Only enable if you explicitly need public access.',
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
            fix: 'hackmyagent rollback',
            guidance: 'Auto-fixes were applied to this configuration. Use rollback to revert if any fix caused unexpected behavior.',
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
            guidance: 'The auto-fix could not write changes to the configuration file. Verify the file is not read-only and that you have write permissions.',
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

        // Skip node_modules, .git, and backup directories
        if (entryName === 'node_modules' || entryName === '.git' || entryName === '.hackmyagent-backup') {
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
        guidance: 'Session and token files contain credentials that grant access to messaging platforms. If committed to git, anyone with repo access can hijack these sessions.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
          // Exclude matches inside defensive/governance context
          // SOUL.md templates quote attack phrases to teach defense against them
          const matchIdx = content.indexOf(match[0]);
          const surroundingStart = Math.max(0, matchIdx - 200);
          const surroundingEnd = Math.min(content.length, matchIdx + match[0].length + 100);
          const surrounding = content.slice(surroundingStart, surroundingEnd).toLowerCase();
          const isDefensive = /must never|forbidden|should not|must not|never comply|resist|reject|refuse|do not|defense|hardening|such as|attempt|detect/i.test(surrounding);
          // Also check if the document is a governance doc (3+ constraint phrases)
          const constraintCount = (content.match(/must never|must not|must always|should not|forbidden|prohibited|restricted to|shall not/gi) || []).length;
          if (isDefensive || constraintCount >= 3) continue;

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
            guidance: 'SOUL.md defines agent behavior. Prompt injection patterns embedded here can override safety instructions and make the agent act maliciously.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
            guidance: 'Daemons running as root have unrestricted system access. A compromised root-level daemon can modify any file, install backdoors, or pivot to other systems.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
            fix: 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
            guidance: 'Plaintext API keys in .env files can be accidentally committed to version control and extracted by any process that reads the file.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
            guidance: 'Agent memory files can be poisoned with prompt injections, eval calls, or base64-encoded payloads that execute when the agent loads its context.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
          guidance: 'Auto-following untrusted agents can expose your agent to malicious instructions, data exfiltration, or prompt injection from compromised peers.',
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
          guidance: 'Unrestricted elevated execution gives tools maximum system privileges without approval gates. This bypasses all safety checks for destructive operations.',
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
          guidance: 'Without sandbox isolation, tool execution has direct access to the host filesystem, network, and processes. Enable sandboxing to contain potential damage.',
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
          fix: 'openssl rand -base64 32',
          guidance: 'Short tokens are vulnerable to brute-force attacks. Use at least 24 characters of cryptographically random data for authentication tokens.',
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
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
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
        fix: `hackmyagent check ${relativePath}`,
        guidance: 'Unverified publishers cannot be trusted. Add publisher: and publisher_verified: true to skill frontmatter after DNS TXT record verification.',
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
        fix: 'Add registry_attestation: to skill frontmatter after registry submission',
        guidance: 'Unregistered skills have no community trust signal. Register with a trusted registry to enable trust scoring and vulnerability alerts.',
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
          fix: `rm ${relativePath}`,
          guidance: 'This skill matches known malicious patterns from the ClawHavoc campaign. Remove immediately and audit any systems it had access to.',
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
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Without an installed_hash, modifications to the skill cannot be detected. The hash enables tamper detection on every scan.',
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
            fix: `rm ${relativePath}`,
            guidance: 'This skill contains a known ClawHavoc command-and-control IP address. Remove immediately and check network logs for connections to this IP.',
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
            fix: `rm ${relativePath}`,
            guidance: 'This skill references a known ClawHavoc malware payload filename. Remove and scan for other indicators of compromise.',
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
            fix: 'Remove the download/execute instruction from this skill',
            guidance: 'ClickFix patterns trick users into downloading and executing malware. This technique is associated with the ClawHavoc campaign.',
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
          fix: 'Remove the archive password reference from this skill',
          guidance: 'Password-protected archives are a common malware distribution technique to bypass antivirus scanning. Investigate the archive source.',
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
            fix: 'npm install openclaw@latest',
            guidance: 'CVE-2026-25253 (CVSS 8.8) enables WebSocket hijacking for remote code execution. Upgrade to v2026.1.29 or later which includes the fix.',
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
              fix: 'npm install openclaw@latest',
              guidance: 'CVE-2026-25157 (CVSS 7.8) allows OS command injection via unescaped SSH project paths. Upgrade to v2026.1.29 or later which includes the fix.',
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
              guidance: 'CVE-2026-25157 (CVSS 7.8) allows OS command injection via unescaped SSH project paths. Your version includes the fix.',
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
              fix: 'npm install openclaw@latest',
              guidance: 'CVE-2026-24763 (CVSS 8.8) allows command injection through unsafe PATH handling in Docker sandbox. Upgrade to v2026.1.29 or later which includes the fix.',
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
              guidance: 'CVE-2026-24763 (CVSS 8.8) allows command injection through unsafe PATH handling in Docker sandbox. Your version includes the fix.',
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
            guidance: 'Without origin restrictions, the control UI can be accessed from any origin. Adding allowedOrigins provides defense-in-depth against cross-origin attacks.',
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
            guidance: 'Origin restrictions prevent cross-origin attacks against the control UI. Your configuration is correctly limiting allowed origins.',
          });
        }
      } catch {
        continue;
      }
    }

    return findings;
  }

  /**
   * Recursively find source files (.ts, .js, .mjs, .cjs, .tsx, .jsx)
   * Skips node_modules, dist, .git, and hidden directories
   */
  private async findSourceFiles(
    dir: string,
    baseDir: string,
    depth: number = 0
  ): Promise<string[]> {
    if (depth > 10) return [];

    const sourceExtensions = new Set(['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx']);
    const skipDirs = new Set(['node_modules', 'dist', '.git']);
    const files: string[] = [];

    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return files;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // Validate path is within directory (no path traversal)
      if (!this.isPathWithinDirectory(fullPath, baseDir)) {
        continue;
      }

      if (entry.isDirectory()) {
        // Skip node_modules, dist, .git, and hidden directories
        if (skipDirs.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;

        // Skip symlinks to prevent path traversal
        try {
          const stats = await fs.lstat(fullPath);
          if (stats.isSymbolicLink()) continue;
        } catch {
          continue;
        }

        const subFiles = await this.findSourceFiles(fullPath, baseDir, depth + 1);
        files.push(...subFiles);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (sourceExtensions.has(ext)) {
          files.push(fullPath);
        }
      }
    }

    return files;
  }

  /**
   * Walk a directory recursively and return files matching the given extensions.
   * Skips node_modules, dist, .git, and hidden directories.
   */
  private async walkDirectory(
    dir: string,
    extensions: string[],
    depth: number = 0,
    maxDepth: number = 10
  ): Promise<string[]> {
    if (depth > maxDepth) return [];

    const extSet = new Set(extensions.map((e) => e.toLowerCase()));
    const skipDirs = new Set(['node_modules', 'dist', '.git', '__pycache__', '.venv']);
    const files: string[] = [];

    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return files;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;
        const subFiles = await this.walkDirectory(fullPath, extensions, depth + 1, maxDepth);
        files.push(...subFiles);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extSet.has(ext)) {
          files.push(fullPath);
        }
      }
    }

    return files;
  }

  /**
   * Check for memory/context poisoning risks
   * Detects patterns that could allow attackers to poison agent memory or conversation context
   */
  private async checkMemoryPoisoning(targetDir: string, _autoFix: boolean): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // MEM-001: Unvalidated memory persistence
    // Check for memory/context files that accept external input without validation
    const memoryFiles = ['memory.json', 'context.json', '.memory', 'agent-memory.json', 'conversation-history.json'];
    for (const memFile of memoryFiles) {
      const filePath = path.join(targetDir, memFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        // Check if memory file is world-writable or contains unvalidated external refs
        if (content.includes('$ref') || content.includes('__proto__') || content.includes('constructor')) {
          findings.push({
            checkId: 'MEM-001',
            name: 'Unvalidated memory persistence',
            description: 'Memory file contains prototype pollution vectors or unvalidated external references that could be exploited to inject malicious context',
            category: 'memory-poisoning',
            severity: 'high',
            passed: false,
            message: `Memory file ${memFile} contains potentially dangerous patterns ($ref, __proto__, constructor)`,
            fixable: false,
            file: memFile,
            fix: 'Sanitize all memory entries before persistence. Remove __proto__ and constructor keys. Validate $ref URIs.',
            guidance: 'Prototype pollution via __proto__ or constructor can alter object behavior. External $ref URIs can load malicious content into agent memory at runtime.',
          });
        }
      } catch { /* file doesn't exist - skip */ }
    }

    // MEM-002: No memory integrity verification
    // Check if conversation/memory files have integrity checks
    const configFiles = ['agent-config.json', 'config.json', 'settings.json', '.agent.json'];
    for (const cfgFile of configFiles) {
      const filePath = path.join(targetDir, cfgFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.memory || config.context || config.conversationHistory) {
          const hasIntegrity = config.memoryIntegrity || config.contextVerification ||
                             config.memory?.signatureVerification || config.memory?.hashValidation;
          if (!hasIntegrity) {
            findings.push({
              checkId: 'MEM-002',
              name: 'No memory integrity verification',
              description: 'Agent configuration enables memory/context persistence without integrity verification. An attacker with file access could inject malicious context.',
              category: 'memory-poisoning',
              severity: 'medium',
              passed: false,
              message: `${cfgFile} enables memory persistence without integrity checks`,
              fixable: false,
              file: cfgFile,
              fix: 'Enable memory integrity verification: add hash validation or signature checks for persisted context.',
              guidance: 'Without integrity checks, an attacker with file access can modify persisted memory to inject malicious instructions that the agent will trust on reload.',
            });
          }
        }
      } catch { /* skip */ }
    }

    // MEM-003: Context window overflow risk
    // Check for agents that load large context without size limits
    for (const cfgFile of configFiles) {
      const filePath = path.join(targetDir, cfgFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.contextWindow || config.maxTokens || config.memory) {
          const hasLimits = config.maxContextSize || config.contextWindow?.maxSize ||
                           config.memory?.maxEntries || config.memory?.maxSize;
          if (!hasLimits) {
            findings.push({
              checkId: 'MEM-003',
              name: 'No context size limits',
              description: 'Agent loads context/memory without size limits. An attacker could craft inputs that overflow the context window, pushing safety instructions out of scope.',
              category: 'memory-poisoning',
              severity: 'medium',
              passed: false,
              message: `${cfgFile} has no context size limits configured`,
              fixable: false,
              file: cfgFile,
              fix: 'Set explicit context size limits: maxContextSize, memory.maxEntries, or memory.maxSize.',
              guidance: 'Without size limits, an attacker can craft inputs that overflow the context window, pushing safety instructions out of scope and taking over agent behavior.',
            });
          }
        }
      } catch { /* skip */ }
    }

    // MEM-004: Shared memory without isolation
    // Check for multi-agent setups with shared memory
    const multiAgentFiles = ['agents.json', 'orchestrator.json', 'multi-agent.json', '.agents'];
    for (const maFile of multiAgentFiles) {
      const filePath = path.join(targetDir, maFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        const agents = config.agents || config.workers || [];
        if (Array.isArray(agents) && agents.length > 1) {
          const sharedMem = config.sharedMemory || config.shared?.memory || config.commonContext;
          if (sharedMem) {
            const hasIsolation = sharedMem.isolation || sharedMem.sandboxed || sharedMem.perAgent;
            if (!hasIsolation) {
              findings.push({
                checkId: 'MEM-004',
                name: 'Shared memory without isolation',
                description: 'Multiple agents share memory without isolation boundaries. A compromised agent could poison the shared context to influence other agents.',
                category: 'memory-poisoning',
                severity: 'high',
                passed: false,
                message: `${maFile} configures shared memory for ${agents.length} agents without isolation`,
                fixable: false,
                file: maFile,
                fix: 'Enable memory isolation: set sharedMemory.isolation=true or use per-agent memory scopes.',
                guidance: 'Shared memory without isolation lets a compromised agent poison context used by all other agents. Use per-agent scopes to prevent cross-agent influence.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }

    // MEM-005: Conversation history injection
    // Check source files for patterns that build prompts from unvalidated history
    try {
      const srcDir = path.join(targetDir, 'src');
      const srcExists = await fs.access(srcDir).then(() => true).catch(() => false);
      if (srcExists) {
        const files = await this.walkDirectory(srcDir, ['.ts', '.js', '.py', '.mjs']);
        for (const file of files.slice(0, 50)) {
          try {
            const content = await fs.readFile(file, 'utf-8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];
              // Detect direct concatenation of history into system prompts
              if ((line.includes('systemPrompt') || line.includes('system_prompt') || line.includes('system_message')) &&
                  (line.includes('history') || line.includes('previousMessages') || line.includes('conversation'))) {
                if (!line.includes('sanitize') && !line.includes('validate') && !line.includes('filter')) {
                  findings.push({
                    checkId: 'MEM-005',
                    name: 'Conversation history injection',
                    description: 'System prompt includes unvalidated conversation history. An attacker could craft messages in history that inject instructions into the system prompt.',
                    category: 'memory-poisoning',
                    severity: 'high',
                    passed: false,
                    message: 'System prompt concatenates unvalidated conversation history',
                    fixable: false,
                    file: path.relative(targetDir, file),
                    line: i + 1,
                    fix: 'Sanitize conversation history before including in system prompts. Strip instruction-like patterns.',
                    guidance: 'Unvalidated conversation history concatenated into system prompts enables indirect prompt injection. Attackers can craft messages that inject instructions.',
                  });
                  break; // One finding per file
                }
              }
            }
          } catch { /* skip unreadable */ }
        }
      }
    } catch { /* skip */ }

    return findings;
  }

  /**
   * Check for RAG (Retrieval-Augmented Generation) poisoning risks
   * Detects patterns that could allow attackers to inject malicious content into RAG pipelines
   */
  private async checkRAGPoisoning(targetDir: string, _autoFix: boolean): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // RAG-001: Unvalidated retrieval sources
    const ragConfigFiles = ['rag.json', 'retrieval.json', 'vector-store.json', 'embeddings.json'];
    for (const ragFile of ragConfigFiles) {
      const filePath = path.join(targetDir, ragFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        const sources = config.sources || config.dataSources || config.indices || [];
        if (Array.isArray(sources)) {
          for (const source of sources) {
            const sourceUrl = source.url || source.endpoint || source.uri || '';
            if (sourceUrl && !source.verified && !source.trustedSource && !source.signatureCheck) {
              findings.push({
                checkId: 'RAG-001',
                name: 'Unvalidated RAG retrieval source',
                description: 'RAG pipeline retrieves from an unverified source. An attacker who controls the source could inject malicious content into agent responses.',
                category: 'rag-poisoning',
                severity: 'high',
                passed: false,
                message: `RAG source ${sourceUrl} has no verification or trust validation`,
                fixable: false,
                file: ragFile,
                fix: 'Add source verification: set trustedSource=true only for validated endpoints, or enable signatureCheck.',
                guidance: 'Unverified RAG sources can be compromised to inject malicious instructions into agent context. Verify sources with signatures or explicit trust markers.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }

    // RAG-002: No content sanitization in retrieval pipeline
    try {
      const srcDir = path.join(targetDir, 'src');
      const srcExists = await fs.access(srcDir).then(() => true).catch(() => false);
      if (srcExists) {
        const files = await this.walkDirectory(srcDir, ['.ts', '.js', '.py', '.mjs']);
        for (const file of files.slice(0, 50)) {
          try {
            const content = await fs.readFile(file, 'utf-8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];
              if ((line.includes('retrieve') || line.includes('vectorSearch') || line.includes('similarity_search') ||
                   line.includes('query_engine')) &&
                  (line.includes('context') || line.includes('prompt') || line.includes('augment'))) {
                // Check surrounding lines for sanitization
                const surroundingLines = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join(' ');
                if (!surroundingLines.includes('sanitize') && !surroundingLines.includes('validate') &&
                    !surroundingLines.includes('filter') && !surroundingLines.includes('escape')) {
                  findings.push({
                    checkId: 'RAG-002',
                    name: 'No RAG content sanitization',
                    description: 'Retrieved content is passed to the LLM without sanitization. Poisoned documents could inject instructions into the prompt.',
                    category: 'rag-poisoning',
                    severity: 'high',
                    passed: false,
                    message: 'Retrieved content flows to LLM without sanitization',
                    fixable: false,
                    file: path.relative(targetDir, file),
                    line: i + 1,
                    fix: 'Sanitize retrieved content before including in prompts. Strip instruction-like patterns and markup.',
                    guidance: 'Poisoned documents in a vector store can contain prompt injections that override agent behavior when retrieved. Sanitize before including in prompts.',
                  });
                  break;
                }
              }
            }
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }

    // RAG-003: Public-writable vector store
    for (const ragFile of ragConfigFiles) {
      const filePath = path.join(targetDir, ragFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.writeAccess === 'public' || config.allowPublicIngestion || config.openIngestion) {
          findings.push({
            checkId: 'RAG-003',
            name: 'Public-writable vector store',
            description: 'Vector store allows public write access. An attacker could insert poisoned documents that will be retrieved and influence agent responses.',
            category: 'rag-poisoning',
            severity: 'critical',
            passed: false,
            message: `${ragFile} allows public write access to vector store`,
            fixable: false,
            file: ragFile,
            fix: 'Restrict vector store write access. Require authentication for document ingestion.',
            guidance: 'Public-writable vector stores let anyone inject poisoned documents. These documents are retrieved by the agent and can influence its responses and behavior.',
          });
        }
      } catch { /* skip */ }
    }

    // RAG-004: No provenance tracking on retrieved content
    for (const ragFile of ragConfigFiles) {
      const filePath = path.join(targetDir, ragFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.sources || config.dataSources || config.indices) {
          if (!config.provenance && !config.sourceTracking && !config.metadata?.trackSource) {
            findings.push({
              checkId: 'RAG-004',
              name: 'No provenance tracking',
              description: 'RAG pipeline does not track provenance of retrieved content. Without provenance, poisoned content cannot be traced back to its source.',
              category: 'rag-poisoning',
              severity: 'medium',
              passed: false,
              message: `${ragFile} has no content provenance tracking`,
              fixable: false,
              file: ragFile,
              fix: 'Enable provenance tracking: set sourceTracking=true to track which source each document came from.',
              guidance: 'Without provenance tracking, poisoned content cannot be traced to its source during incident response. Source tracking enables rapid identification and removal.',
            });
          }
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Check for agent identity spoofing risks
   * Detects missing or weak agent identity verification
   */
  private async checkAgentIdentity(targetDir: string, _autoFix: boolean): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // AIM-001: No agent identity declaration
    const identityFiles = ['agent-card.json', 'agent.json', '.well-known/agent.json', 'aim.json'];
    let hasIdentity = false;
    for (const idFile of identityFiles) {
      const filePath = path.join(targetDir, idFile);
      try {
        await fs.access(filePath);
        hasIdentity = true;

        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);

        // AIM-002: Identity without cryptographic binding
        // Skip if authentication is explicitly declared as "none" (local/CLI tools with no network identity).
        const hasExplicitNoAuth = config.authentication?.type === 'none';
        if ((config.agentId || config.name || config.identity) && !hasExplicitNoAuth) {
          if (!config.publicKey && !config.keyId && !config.jwk && !config.x509) {
            // Soften to MEDIUM inside examples/templates/docs/samples —
            // these are schema demonstrations, not production identities.
            // An insecure example still teaches insecure practice, so we
            // report (not skip) but lower the alarm. [CSR-002].
            // Check both the relative file path AND targetDir, because
            // the scanner only looks for agent-card.json at the scan
            // root — when the user scans `.../examples/my-agent/`,
            // idFile is just `agent-card.json` with no example marker,
            // but targetDir itself carries it.
            const isExample = isExamplePath(idFile) || isExamplePath(targetDir);
            findings.push({
              checkId: 'AIM-002',
              name: 'Identity without cryptographic binding',
              description: 'Agent declares an identity but has no cryptographic key binding. Any agent could claim this identity without proof.',
              category: 'identity-spoofing',
              severity: isExample ? 'medium' : 'high',
              passed: false,
              message: isExample
                ? `${idFile} is an example/template — identity schema shown without cryptographic key binding`
                : `${idFile} declares identity without cryptographic key binding`,
              fixable: false,
              file: idFile,
              fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
              guidance: 'Without cryptographic binding, any agent can impersonate this identity. Ed25519 key pairs provide proof of identity through digital signatures.',
            });
          }
        }

        // AIM-003: No identity verification endpoint
        if (config.agentId || config.identity) {
          if (!config.verificationEndpoint && !config.oidcIssuer && !config.wellKnown) {
            findings.push({
              checkId: 'AIM-003',
              name: 'No identity verification endpoint',
              description: 'Agent identity has no verification endpoint. Other agents cannot verify this agent\'s identity claims.',
              category: 'identity-spoofing',
              severity: 'medium',
              passed: false,
              message: `${idFile} has no identity verification endpoint (verificationEndpoint, oidcIssuer, or wellKnown)`,
              fixable: false,
              file: idFile,
              fix: 'Add a verification endpoint: verificationEndpoint URL or oidcIssuer for federated identity.',
              guidance: 'Without a verification endpoint, other agents and registries cannot verify identity claims. This enables identity spoofing in multi-agent systems.',
            });
          }
        }
      } catch { /* skip */ }
    }

    // Also check package.json or A2A agent card
    if (!hasIdentity) {
      try {
        const pkgPath = path.join(targetDir, 'package.json');
        const pkgContent = await fs.readFile(pkgPath, 'utf-8');
        const pkg = JSON.parse(pkgContent);
        if (pkg.agentCard || pkg.a2a || pkg.keywords?.some((k: string) => k.includes('agent') || k.includes('a2a'))) {
          findings.push({
            checkId: 'AIM-001',
            name: 'No agent identity declaration',
            description: 'Project appears to be an AI agent but has no formal identity declaration. Without identity, the agent cannot be verified by other agents or registries.',
            category: 'identity-spoofing',
            severity: 'medium',
            passed: false,
            message: 'Agent project has no identity declaration file (agent-card.json, agent.json, aim.json)',
            fixable: false,
            file: 'package.json',
            fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
            guidance: 'Without a formal identity declaration, the agent cannot be verified by other agents, registries, or trust frameworks. Creates an Ed25519 key pair with audit logging.',
          });
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Check for agent DNA/behavioral fingerprint forgery risks
   * Detects integrity issues with agent behavioral profiles
   */
  private async checkAgentDNA(targetDir: string, _autoFix: boolean): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // DNA-001: No behavioral fingerprint
    const dnaFiles = ['agent-dna.json', '.agent-dna', 'behavioral-profile.json'];
    const soulFileNames = ['SOUL.md', 'system-prompt.md', '.cursorrules', 'CLAUDE.md'];
    let hasDna = false;
    let hasSoul = false;
    let foundSoulFile = '';

    for (const dnaFile of dnaFiles) {
      try {
        await fs.access(path.join(targetDir, dnaFile));
        hasDna = true;

        const content = await fs.readFile(path.join(targetDir, dnaFile), 'utf-8');
        const config = JSON.parse(content);

        // DNA-002: Unsigned behavioral profile
        // Require an actual VALUE (hash bytes or signature), not a method descriptor.
        // A string like `verificationMethod: "sha256"` describes HOW to hash but
        // contains no hash value an auditor could verify — it does not count.
        const looksLikeHashValue = (v: unknown): boolean => {
          if (typeof v === 'string') {
            // SHA-256 hex = 64 chars, base64 = 43, "sha256:<hex>" = 71. Require ≥ 32.
            return v.length >= 32;
          }
          if (typeof v === 'object' && v !== null) {
            const obj = v as Record<string, unknown>;
            return looksLikeHashValue(obj.value) || looksLikeHashValue(obj.hash) ||
              looksLikeHashValue(obj.signature) || looksLikeHashValue(obj.digest);
          }
          return false;
        };
        const hasHashOrSig =
          looksLikeHashValue(config.signature) ||
          looksLikeHashValue(config.hash) ||
          looksLikeHashValue(config.contentHash) ||
          looksLikeHashValue(config.behavioralProfile?.contentHash) ||
          looksLikeHashValue(config.behavioralProfile?.signature) ||
          looksLikeHashValue(config.integrityPolicy?.contentHash) ||
          looksLikeHashValue(config.integrityPolicy?.signature);
        if (!hasHashOrSig) {
          findings.push({
            checkId: 'DNA-002',
            name: 'Unsigned behavioral profile',
            description: 'Agent DNA/behavioral profile exists but is not signed. An attacker could modify the profile to change agent behavior without detection.',
            category: 'agent-dna',
            severity: 'high',
            passed: false,
            message: `${dnaFile} has no signature or content hash`,
            fixable: false,
            file: dnaFile,
            fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
            guidance: 'Unsigned behavioral profiles can be silently modified to change agent behavior. Cryptographic signatures enable tamper detection on every load.',
          });
        }

        // DNA-003: No behavioral drift detection
        // Require a real policy value, not just `driftDetection: true`. A boolean
        // toggle without a threshold or baseline cannot actually detect drift —
        // it asserts an intention without configuring the mechanism.
        const isPolicyObject = (v: unknown): boolean =>
          typeof v === 'object' && v !== null && Object.keys(v as object).length > 0;
        const hasDriftDetection =
          (typeof config.baselineHash === 'string' && config.baselineHash.length >= 32) ||
          typeof config.driftThreshold === 'number' ||
          typeof config.integrityPolicy?.driftThreshold === 'number' ||
          isPolicyObject(config.integrityPolicy?.driftDetection) ||
          isPolicyObject(config.monitoringPolicy) ||
          (config.monitoringEnabled === true && (config.monitoringEndpoint || config.monitoringWebhook));
        if (!hasDriftDetection) {
          findings.push({
            checkId: 'DNA-003',
            name: 'No behavioral drift detection',
            description: 'Agent DNA has no drift detection configured. Gradual behavioral changes would go undetected.',
            category: 'agent-dna',
            severity: 'medium',
            passed: false,
            message: `${dnaFile} has no behavioral drift detection (baselineHash, driftThreshold, monitoring)`,
            fixable: false,
            file: dnaFile,
            fix: 'Enable behavioral drift detection: set baselineHash and driftThreshold for continuous monitoring.',
            guidance: 'Without drift detection, gradual behavioral changes (prompt drift, personality shifts) go unnoticed. A baseline hash detects any deviation from expected behavior.',
          });
        }
      } catch { /* skip */ }
    }

    for (const soulFile of soulFileNames) {
      try {
        await fs.access(path.join(targetDir, soulFile));
        hasSoul = true;
        if (!foundSoulFile) foundSoulFile = soulFile;
      } catch { /* skip */ }
    }

    // If agent has a SOUL/system prompt but no DNA fingerprint
    if (hasSoul && !hasDna) {
      // Check if this is actually an agent project
      try {
        const pkgPath = path.join(targetDir, 'package.json');
        const pkgContent = await fs.readFile(pkgPath, 'utf-8');
        const pkg = JSON.parse(pkgContent);
        if (pkg.agentCard || pkg.a2a || pkg.keywords?.some((k: string) => k.includes('agent'))) {
          findings.push({
            checkId: 'DNA-001',
            name: 'No behavioral fingerprint',
            description: 'Agent has behavioral instructions (SOUL.md/system prompt) but no behavioral fingerprint. Without a fingerprint, behavioral integrity cannot be verified.',
            category: 'agent-dna',
            severity: 'medium',
            passed: false,
            message: 'Agent has behavioral instructions but no DNA fingerprint file',
            fixable: false,
            file: foundSoulFile || 'SOUL.md',
            fix: 'Create agent-dna.json with contentHash of SOUL.md, baselineHash, and signature for integrity verification.',
            guidance: 'A behavioral fingerprint enables continuous integrity verification of agent instructions. Without it, modifications to SOUL.md cannot be detected.',
          });
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Check for skill-based memory manipulation risks
   */
  private async checkSkillMemory(targetDir: string, _autoFix: boolean): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // SKILL-MEM-001: Skills with memory write access
    // Check SKILL.md for memory manipulation patterns
    try {
      const skillMdPath = path.join(targetDir, 'SKILL.md');
      const content = await fs.readFile(skillMdPath, 'utf-8');
      const lowerContent = content.toLowerCase();

      if ((lowerContent.includes('memory') || lowerContent.includes('context') || lowerContent.includes('state')) &&
          (lowerContent.includes('write') || lowerContent.includes('modify') || lowerContent.includes('update') || lowerContent.includes('set'))) {
        if (!lowerContent.includes('read-only') && !lowerContent.includes('readonly') && !lowerContent.includes('immutable')) {
          findings.push({
            checkId: 'SKILL-MEM-001',
            name: 'Skill with unrestricted memory access',
            description: 'A skill declares memory/context write capabilities without explicit restrictions. A malicious skill could manipulate agent memory to alter future behavior.',
            category: 'skill-memory',
            severity: 'high',
            passed: false,
            message: 'SKILL.md declares memory write access without read-only constraints',
            fixable: false,
            file: 'SKILL.md',
            fix: 'Restrict skill memory access: declare explicit read-only or scoped-write permissions in SKILL.md.',
            guidance: 'Skills with unrestricted memory write access can poison agent context, alter future responses, or plant persistent backdoors that survive restarts.',
          });
        }
      }
    } catch { /* no SKILL.md */ }

    // Check skills directory for memory manipulation patterns
    try {
      const skillsDir = path.join(targetDir, 'skills');
      const dirExists = await fs.access(skillsDir).then(() => true).catch(() => false);
      if (dirExists) {
        const files = await this.walkDirectory(skillsDir, ['.ts', '.js', '.py', '.md']);
        for (const file of files.slice(0, 30)) {
          try {
            const content = await fs.readFile(file, 'utf-8');
            if ((content.includes('writeMemory') || content.includes('setContext') ||
                 content.includes('updateState') || content.includes('persistMemory')) &&
                !content.includes('readOnly') && !content.includes('read_only')) {
              findings.push({
                checkId: 'SKILL-MEM-001',
                name: 'Skill with unrestricted memory access',
                description: 'Skill file contains memory write operations without read-only guards.',
                category: 'skill-memory',
                severity: 'high',
                passed: false,
                message: 'Skill writes to agent memory without restrictions',
                fixable: false,
                file: path.relative(targetDir, file),
                fix: 'Add read-only guards or scope memory writes to skill-specific namespaces.',
                guidance: 'Unrestricted memory writes from skills can alter agent state across all contexts. Scope writes to skill-specific namespaces to prevent cross-skill interference.',
              });
              break; // One per skill dir
            }
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }

    return findings;
  }

  /**
   * Check for Unicode steganography attacks (GlassWorm detection)
   * Detects invisible codepoints, decoder patterns, eval on empty strings,
   * and tag character block presence in source files.
   */
  private async checkUnicodeSteganography(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    // Scan expanded file types beyond JS/TS (configs, docs, and Python are attack surfaces too)
    const stegoExtensions = ['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx', '.py', '.md', '.txt', '.yaml', '.yml', '.json', '.toml'];
    const sourceFiles = await this.walkDirectory(targetDir, stegoExtensions);

    for (const filePath of sourceFiles) {
      const relativePath = path.relative(targetDir, filePath);
      let rawBuffer: Buffer;
      try {
        rawBuffer = await fs.readFile(filePath);
      } catch {
        continue;
      }

      // Skip files larger than MAX_FILE_SIZE
      if (rawBuffer.length > MAX_FILE_SIZE) continue;

      // UNICODE-STEGO-001: Invisible Codepoint Detection
      // Scan for:
      //   - Variation selectors U+FE00-FE0F (UTF-8: EF B8 80-8F)
      //   - Tag characters U+E0100-E01EF (UTF-8: F3 A0 84 80 - F3 A0 87 AF)
      //   - Zero-width chars: U+200B (E2 80 8B), U+200C (E2 80 8C), U+200D (E2 80 8D)
      //   - Mid-file BOM: U+FEFF (EF BB BF) -- skip offset 0
      //   - Bidi overrides: U+202A-202E (E2 80 AA-AE), U+2066-2069 (E2 81 A6-A9)

      // Skip ML training corpora and datasets entirely. These directories
      // intentionally contain adversarial Unicode (the model learns to
      // detect it); firing stego findings on training data teaches the
      // wrong signal and blocks legitimate ML repos. [CSR-003]+[CDS-023].
      if (isCorpusPath(relativePath)) {
        continue;
      }

      // Skip variation selector checks for documentation files where emoji are
      // decorative, not steganographic. The isEmojiVariationSelector heuristic
      // can't cover all valid emoji bases across Unicode versions, and FE0F in
      // docs is essentially always an emoji presentation selector.
      const isDocFile = /\.(md|txt)$/i.test(relativePath) ||
        /^(README|CHANGELOG|CONTRIBUTING|AGENTS|CLAUDE|LICENSE|AUTHORS|HISTORY)/i.test(path.basename(relativePath));

      let hasVariationSelectors = false;
      let variationSelectorLine = 1;
      let hasTagCharsIn001 = false;
      let tagCharLine001 = 1;
      let hasZeroWidth = false;
      let zeroWidthLine = 1;
      let hasMidFileBom = false;
      let midFileBomLine = 1;
      let hasBidiOverride = false;
      let bidiOverrideLine = 1;

      let currentLine = 1;
      for (let i = 0; i < rawBuffer.length; i++) {
        if (rawBuffer[i] === 0x0A) {
          currentLine++;
          continue;
        }
        // Variation selectors: EF B8 80-8F (U+FE00-FE0F)
        // Skip entirely for doc files (variation selectors in markdown/changelogs
        // are virtually always emoji presentation selectors, not steganography).
        // For source files, check if preceded by a known emoji base character.
        if (
          !isDocFile &&
          rawBuffer[i] === 0xEF &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xB8 &&
          rawBuffer[i + 2] >= 0x80 &&
          rawBuffer[i + 2] <= 0x8F
        ) {
          // Check if this is an emoji presentation selector (FE0F after emoji base)
          if (rawBuffer[i + 2] === 0x8F && isEmojiVariationSelector(rawBuffer, i)) {
            // Legitimate emoji — skip
          } else if (!hasVariationSelectors) {
            hasVariationSelectors = true;
            variationSelectorLine = currentLine;
          }
        }
        // Tag characters in U+E0100-E01EF: F3 A0 84 80 through F3 A0 87 AF
        if (
          rawBuffer[i] === 0xF3 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xA0 &&
          rawBuffer[i + 2] >= 0x84 &&
          rawBuffer[i + 2] <= 0x87
        ) {
          if (!hasTagCharsIn001) {
            hasTagCharsIn001 = true;
            tagCharLine001 = currentLine;
          }
        }
        // Zero-width chars: U+200B/200C/200D = E2 80 8B/8C/8D
        if (
          rawBuffer[i] === 0xE2 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0x80 &&
          rawBuffer[i + 2] >= 0x8B &&
          rawBuffer[i + 2] <= 0x8D
        ) {
          if (!hasZeroWidth) {
            hasZeroWidth = true;
            zeroWidthLine = currentLine;
          }
        }
        // Mid-file BOM: U+FEFF = EF BB BF (skip if at offset 0)
        if (
          i > 0 &&
          rawBuffer[i] === 0xEF &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xBB &&
          rawBuffer[i + 2] === 0xBF
        ) {
          if (!hasMidFileBom) {
            hasMidFileBom = true;
            midFileBomLine = currentLine;
          }
        }
        // Bidi overrides: U+202A-202E = E2 80 AA-AE
        if (
          rawBuffer[i] === 0xE2 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0x80 &&
          rawBuffer[i + 2] >= 0xAA &&
          rawBuffer[i + 2] <= 0xAE
        ) {
          if (!hasBidiOverride) {
            hasBidiOverride = true;
            bidiOverrideLine = currentLine;
          }
        }
        // Bidi isolates: U+2066-2069 = E2 81 A6-A9
        if (
          rawBuffer[i] === 0xE2 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0x81 &&
          rawBuffer[i + 2] >= 0xA6 &&
          rawBuffer[i + 2] <= 0xA9
        ) {
          if (!hasBidiOverride) {
            hasBidiOverride = true;
            bidiOverrideLine = currentLine;
          }
        }
      }

      // Bidi and variation/tag chars are critical; zero-width-only is high
      const hasCriticalInvisible = hasVariationSelectors || hasTagCharsIn001 || hasBidiOverride;
      const hasAnyInvisible = hasCriticalInvisible || hasZeroWidth || hasMidFileBom;

      if (hasAnyInvisible) {
        const detectedTypes: string[] = [];
        if (hasVariationSelectors) detectedTypes.push('variation selectors (U+FE00-FE0F)');
        if (hasTagCharsIn001) detectedTypes.push('tag characters (U+E0100-E01EF)');
        if (hasZeroWidth) detectedTypes.push('zero-width characters (U+200B-200D)');
        if (hasMidFileBom) detectedTypes.push('mid-file BOM (U+FEFF)');
        if (hasBidiOverride) detectedTypes.push('bidi overrides (U+202A-202E, U+2066-2069)');

        // Determine first line hit for reporting
        const firstLine = Math.min(
          ...[
            hasVariationSelectors ? variationSelectorLine : Infinity,
            hasTagCharsIn001 ? tagCharLine001 : Infinity,
            hasZeroWidth ? zeroWidthLine : Infinity,
            hasMidFileBom ? midFileBomLine : Infinity,
            hasBidiOverride ? bidiOverrideLine : Infinity,
          ]
        );

        findings.push({
          checkId: 'UNICODE-STEGO-001',
          name: 'Invisible Unicode Codepoints Detected',
          description: 'Source file contains invisible Unicode codepoints that can hide malicious payloads (GlassWorm attack vector)',
          category: 'unicode-stego',
          severity: hasCriticalInvisible ? 'critical' : 'high',
          passed: false,
          message: `Found ${detectedTypes.join(' and ')} in ${relativePath}`,
          file: relativePath,
          line: firstLine,
          fixable: false,
          fix: 'xxd ' + shellEscape(relativePath) + ' | grep -iE "e280[8-9a-e]|efbb|efb8|f3a0"',
          guidance: 'Invisible Unicode codepoints (zero-width chars, variation selectors, tag characters, bidi overrides) can hide malicious payloads in source code. This is the GlassWorm attack vector. Inspect with a hex editor and remove all non-functional invisible characters.',
        });
      }

      // UNICODE-STEGO-002: GlassWorm Decoder Pattern
      // Detect .codePointAt( combined with hex literals in the variation selector or tag range
      const content = rawBuffer.toString('utf-8');
      const lines = content.split('\n');
      let hasCodePointAt = false;
      let hasHexLiteral = false;
      let decoderLine = 1;

      const hexPattern = /0x(?:FE0[0-9A-Fa-f]|fe0[0-9a-f]|E010[0-9A-Fa-f]|e010[0-9a-f]|E01[0-9A-Ea-e][0-9A-Fa-f]|e01[0-9a-e][0-9a-f])/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > MAX_LINE_LENGTH) continue;
        if (line.includes('.codePointAt(')) {
          hasCodePointAt = true;
          if (!decoderLine || decoderLine === 1) decoderLine = i + 1;
        }
        if (hexPattern.test(line)) {
          hasHexLiteral = true;
        }
      }

      // Skip only if this is security detection code. Three conditions, ALL required:
      //   1. File path indicates analyzer/scanner (attacker-controllable, weak signal)
      //   2. Hex literals appear in range-comparison context, not assignments (weak signal)
      //   3. No String.fromCodePoint/fromCharCode CALL — the decoder half of GlassWorm
      //      reconstitutes a string from codepoints; detection code only inspects them.
      //      This is the strong signal that prevents filename-based bypass.
      const hasStringReconstitution = /String\.from(?:CodePoint|CharCode)\s*\(/.test(content);
      const isDetectionCode =
        !hasStringReconstitution &&
        /(?:>=|<=|===|!==)\s*0x(?:FE0|E010)/i.test(content) &&
        /(?:analyz|detect|scan|check|inspect|enhanc|stego)/i.test(relativePath);

      if (hasCodePointAt && hasHexLiteral && !isDetectionCode) {
        findings.push({
          checkId: 'UNICODE-STEGO-002',
          name: 'GlassWorm Decoder Pattern Detected',
          description: 'Source file contains .codePointAt() usage combined with Unicode variation selector or tag character hex literals - this is the decoder half of a GlassWorm attack',
          category: 'unicode-stego',
          severity: 'critical',
          passed: false,
          message: `Found GlassWorm decoder pattern (.codePointAt + hex range literals) in ${relativePath}`,
          file: relativePath,
          line: decoderLine,
          fixable: false,
          fix: 'Review the file for suspicious .codePointAt() logic that decodes hidden data from variation selectors (0xFE00-0xFE0F) or tag characters (0xE0100-0xE01EF). Remove the decoder function.',
          guidance: 'The GlassWorm attack encodes malicious payloads in invisible Unicode characters and uses .codePointAt() to decode them at runtime. This is the decoder half of the attack.',
        });
      }

      // UNICODE-STEGO-003: Eval on Empty String
      // Find eval() or Function() calls where the string argument has few visible chars but many bytes
      const evalPattern = /(?:eval|Function)\s*\(\s*(['"`])([\s\S]*?)\1\s*\)/g;
      let evalMatch;
      while ((evalMatch = evalPattern.exec(content)) !== null) {
        const matchedStr = evalMatch[2];
        // Count truly visible characters by excluding invisible Unicode ranges:
        // - Control characters (U+0000-001F, U+007F-009F)
        // - Variation selectors (U+FE00-FE0F)
        // - Zero-width characters (U+200B-200F, U+2060, U+FEFF)
        // - Tag characters (U+E0000-E01EF)
        // - Combining marks and other invisible codepoints
        let visibleChars = 0;
        for (const ch of matchedStr) {
          const cp = ch.codePointAt(0)!;
          if (cp <= 0x1F) continue; // C0 controls
          if (cp >= 0x7F && cp <= 0x9F) continue; // C1 controls
          if (cp >= 0x200B && cp <= 0x200F) continue; // zero-width chars
          if (cp === 0x2060 || cp === 0xFEFF) continue; // word joiner, BOM
          if (cp >= 0xFE00 && cp <= 0xFE0F) continue; // variation selectors
          if (cp >= 0xE0000 && cp <= 0xE01EF) continue; // tag characters
          if (cp >= 0xE0100 && cp <= 0xE01EF) continue; // variation selector supplement
          visibleChars++;
        }
        const byteLength = Buffer.byteLength(matchedStr, 'utf-8');

        if (visibleChars < 5 && byteLength > 100) {
          // Find the line number
          const offset = evalMatch.index;
          let evalLine = 1;
          for (let j = 0; j < offset && j < content.length; j++) {
            if (content[j] === '\n') evalLine++;
          }

          findings.push({
            checkId: 'UNICODE-STEGO-003',
            name: 'Eval on String with Hidden Payload',
            description: 'eval() or Function() is called with a string that has very few visible characters but a large byte footprint - indicates invisible Unicode payload',
            category: 'unicode-stego',
            severity: 'critical',
            passed: false,
            message: `Found eval/Function with ${visibleChars} visible chars but ${byteLength} bytes in ${relativePath}`,
            file: relativePath,
            line: evalLine,
            fixable: false,
            fix: 'node -e "const fs=require(\'fs\'); const s=fs.readFileSync(' + JSON.stringify(relativePath) + ',\'utf8\'); console.log([...s].filter(c=>c.codePointAt(0)>0x200).map(c=>c.codePointAt(0).toString(16)))"',
            guidance: 'eval() or Function() called with mostly invisible characters is a strong indicator of a GlassWorm payload. The string contains hidden Unicode characters encoding malicious code. Remove the eval/Function call and audit the file.',
          });
          break; // One finding per file
        }
      }

      // UNICODE-STEGO-004: Tag Character Block Presence
      // Scan for any U+E0000-U+E01EF characters (broader than 001, covers entire tag block)
      // UTF-8 encoding: F3 A0 80 80 through F3 A0 87 AF
      let hasTagBlock = false;
      let tagBlockLine = 1;
      currentLine = 1;

      for (let i = 0; i < rawBuffer.length; i++) {
        if (rawBuffer[i] === 0x0A) {
          currentLine++;
          continue;
        }
        if (
          rawBuffer[i] === 0xF3 &&
          i + 3 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xA0 &&
          rawBuffer[i + 2] >= 0x80 &&
          rawBuffer[i + 2] <= 0x87
        ) {
          hasTagBlock = true;
          tagBlockLine = currentLine;
          break;
        }
      }

      if (hasTagBlock) {
        // Only add UNICODE-STEGO-004 if we did not already flag tag chars in 001
        // (004 is broader - covers U+E0000-U+E01EF, 001 only covers U+E0100-E01EF)
        const already001 = findings.some(
          (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === relativePath
        );
        if (!already001) {
          findings.push({
            checkId: 'UNICODE-STEGO-004',
            name: 'Unicode Tag Character Block Detected',
            description: 'Source file contains characters from the Unicode Tag block (U+E0000-U+E01EF) which have no visible rendering and can be used to hide data',
            category: 'unicode-stego',
            severity: 'high',
            passed: false,
            message: `Found Unicode tag block characters in ${relativePath}`,
            file: relativePath,
            line: tagBlockLine,
            fixable: false,
            fix: 'xxd ' + shellEscape(relativePath) + ' | grep "f3a0"',
            guidance: 'Unicode Tag block characters (U+E0000-U+E01EF) are invisible and have no legitimate use in source code. They can encode hidden data or malicious payloads. Remove all tag block characters found.',
          });
        }
      }

      // UNICODE-STEGO-005: Homoglyph Confusable Detection
      // Detect Cyrillic/Greek characters that look identical to Latin but have different codepoints.
      // These can be used to bypass code review and hide malicious identifiers.
      const homoglyphCodepoints = new Set([
        // Cyrillic uppercase that look like Latin: A, B, C, E, H, K, M, O, P, T, X
        0x0410, 0x0412, 0x0421, 0x0415, 0x041D, 0x041A, 0x041C, 0x041E, 0x0420, 0x0422, 0x0425,
        // Cyrillic lowercase that look like Latin: a, e, o, p, c, x
        0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0445,
        // Fullwidth Latin (U+FF21-FF3A, U+FF41-FF5A) -- spot-check common ones
        0xFF21, 0xFF22, 0xFF41, 0xFF42,
      ]);

      let homoglyphFound = false;
      let homoglyphLine = 1;
      let homoglyphChar = '';
      const contentForHomoglyph = content || rawBuffer.toString('utf-8');
      const homoglyphLines = contentForHomoglyph.split('\n');

      // Track markdown code fences: homoglyphs inside ```...``` blocks in .md files
      // are documentation examples, not executable code — skip them.
      const isMarkdown = relativePath.endsWith('.md') || relativePath.endsWith('.txt');
      let inCodeFence = false;

      for (let lineIdx = 0; lineIdx < homoglyphLines.length; lineIdx++) {
        const line = homoglyphLines[lineIdx];
        if (line.length > MAX_LINE_LENGTH) continue;

        // Track code fence boundaries in markdown files
        if (isMarkdown && line.trimStart().startsWith('```')) {
          inCodeFence = !inCodeFence;
          continue;
        }
        // Skip lines inside markdown code fences (documentation examples)
        if (isMarkdown && inCodeFence) continue;

        // Skip comment lines
        const trimmed = line.trimStart();
        if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

        const chars = [...line];
        for (let ci = 0; ci < chars.length; ci++) {
          const cp = chars[ci].codePointAt(0)!;
          if (homoglyphCodepoints.has(cp)) {
            // Check if this Cyrillic char is in a Cyrillic text block (i18n)
            // vs mixed into a Latin word (homoglyph attack).
            // Look at neighboring characters: if surrounded by other Cyrillic
            // or non-Latin chars, it's legitimate i18n text.
            if (isCyrillicInCyrillicContext(chars, ci)) {
              continue; // Legitimate i18n — skip
            }
            homoglyphFound = true;
            homoglyphLine = lineIdx + 1;
            homoglyphChar = `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
            break;
          }
        }
        if (homoglyphFound) break;
      }

      if (homoglyphFound) {
        findings.push({
          checkId: 'UNICODE-STEGO-005',
          name: 'Homoglyph Confusable Characters Detected',
          description: 'Source file contains characters from non-Latin scripts (Cyrillic, Greek, Fullwidth) that visually resemble Latin letters. These can be used to create identifiers that look identical in code review but behave differently at runtime.',
          category: 'unicode-stego',
          severity: 'high',
          passed: false,
          message: `Found homoglyph confusable character (${homoglyphChar}) in ${relativePath} at line ${homoglyphLine}`,
          file: relativePath,
          line: homoglyphLine,
          fixable: false,
          fix: 'node -e "const fs=require(\'fs\'); [...fs.readFileSync(' + JSON.stringify(relativePath) + ',\'utf8\')].forEach((c,i)=>{const cp=c.codePointAt(0); if(cp>0x7F && cp<0xFFFF) console.log(i, cp.toString(16), c)})"',
          guidance: 'Homoglyph confusables (Cyrillic/Greek/Fullwidth characters that look like Latin letters) can create variable names that appear identical in code review but reference different values at runtime. Replace with ASCII equivalents.',
        });
      }
    }

    return findings;
  }

  /**
   * NemoClaw static analysis checks (NEMO-001 through NEMO-010)
   * Detects vulnerability patterns in any codebase: unsafe installs, missing
   * digest verification, injection vectors, secret leaks, deserialization, and
   * egress policy gaps.
   */
  private async checkNemoClawPatterns(
    targetDir: string,
    _shouldFix: boolean,
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Collect source files by extension (max depth 5, skips node_modules/.git/dist/build)
    const shFiles = await this.walkDirectory(targetDir, ['.sh'], 0, 5);
    const tsJsFiles = await this.walkDirectory(targetDir, ['.ts', '.js'], 0, 5);
    const pyFiles = await this.walkDirectory(targetDir, ['.py'], 0, 5);
    const yamlFiles = await this.walkDirectory(targetDir, ['.yaml', '.yml'], 0, 5);

    // Cap file counts to avoid scanning enormous repos
    const maxFiles = 200;
    const cappedSh = shFiles.slice(0, maxFiles);
    const cappedTsJs = tsJsFiles.slice(0, maxFiles);
    const cappedPy = pyFiles.slice(0, maxFiles);
    const cappedYaml = yamlFiles.slice(0, maxFiles);

    // ---------- NEMO-001: Curl-pipe install without checksum ----------
    let nemo001Found = false;
    for (const file of cappedSh) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/curl.*\|\s*(ba)?sh/i.test(line) || /curl.*\|\s*sudo/i.test(line)) {
            // Check surrounding 20 lines for checksum verification
            const windowStart = Math.max(0, i - 10);
            const windowEnd = Math.min(lines.length, i + 11);
            const window = lines.slice(windowStart, windowEnd).join('\n').toLowerCase();
            if (!window.includes('sha256') && !window.includes('checksum') && !window.includes('gpg --verify')) {
              nemo001Found = true;
              findings.push({
                checkId: 'NEMO-001',
                name: 'Curl-pipe install without checksum',
                description: 'A shell script pipes curl output directly into a shell interpreter without verifying a checksum or GPG signature. An attacker who compromises the remote host can inject arbitrary code.',
                category: 'nemo-install',
                severity: 'critical',
                passed: false,
                message: `Curl-pipe install without integrity check at line ${i + 1}`,
                fixable: false,
                file: path.relative(targetDir, file),
                line: i + 1,
                fix: 'Remove the curl-pipe pattern. Download the script to a file first, verify its SHA256 checksum, then execute. Run hackmyagent secure . to reverify after fixing.',
                guidance: 'Piping curl directly to sh executes whatever the remote server returns. A compromised or MITM-ed server can inject arbitrary code. Always download, verify, then execute.',
              });
            }
          }
        }
      } catch { /* skip unreadable */ }
    }
    if (!nemo001Found && cappedSh.length > 0) {
      findings.push({
        checkId: 'NEMO-001',
        name: 'Curl-pipe install without checksum',
        description: 'No curl-pipe-to-shell patterns found without checksum verification.',
        category: 'nemo-install',
        severity: 'critical',
        passed: true,
        message: 'No unsafe curl-pipe installs detected',
        fixable: false,
        guidance: 'Piping curl directly to sh executes whatever the remote server returns. A compromised or MITM-ed server can inject arbitrary code.',
      });
    }

    // ---------- NEMO-002: Blueprint/artifact digest verification gap ----------
    let nemo002Found = false;
    // Check YAML files for empty digest fields
    for (const file of cappedYaml) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/digest:\s*["']?\s*["']?\s*$/.test(line) || /digest:\s*["']{2}/.test(line)) {
            nemo002Found = true;
            findings.push({
              checkId: 'NEMO-002',
              name: 'Empty digest field in blueprint/artifact',
              description: 'A YAML manifest declares a digest field with an empty value. Artifacts without digests cannot be verified for integrity, enabling supply-chain injection.',
              category: 'nemo-integrity',
              severity: 'critical',
              passed: false,
              message: `Empty digest field at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'sha256sum <artifact>',
              guidance: 'Empty digest fields bypass integrity verification entirely. Require non-empty digests and fail builds when they are missing, so tampered artifacts cannot pass.',
            });
          }
        }
      } catch { /* skip */ }
    }
    // Check TS/JS files for digest skip logic
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/if\s*\(\s*!?.*digest\s*&&/.test(line) || /if\s*\(\s*!.*digest\s*\)/.test(line)) {
            nemo002Found = true;
            findings.push({
              checkId: 'NEMO-002',
              name: 'Digest verification skipped on falsy value',
              description: 'Code skips digest verification when the digest field is falsy. An attacker who removes the digest from a manifest bypasses integrity checks entirely.',
              category: 'nemo-integrity',
              severity: 'critical',
              passed: false,
              message: `Digest verification skipped when falsy at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Require non-empty digest; fail verification if digest is missing instead of skipping the check.',
              guidance: 'Skipping digest verification when the value is falsy means an attacker can remove the digest field to bypass integrity checks. Treat missing digest as a hard failure.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo002Found && (cappedYaml.length > 0 || cappedTsJs.length > 0)) {
      findings.push({
        checkId: 'NEMO-002',
        name: 'Blueprint/artifact digest verification gap',
        description: 'No empty digest fields or digest-skip logic found.',
        category: 'nemo-integrity',
        severity: 'critical',
        passed: true,
        message: 'No digest verification gaps detected',
        fixable: false,
        guidance: 'Empty or missing digest fields bypass integrity verification, allowing tampered artifacts to pass through the supply chain unchecked.',
      });
    }

    // ---------- NEMO-003: Hot-reload policy paths reachable from user input ----------
    let nemo003Found = false;
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/policy.*reload|reload.*policy|hot.*reload/i.test(line)) {
            // Check surrounding 10 lines for user input references
            const windowStart = Math.max(0, i - 5);
            const windowEnd = Math.min(lines.length, i + 6);
            const window = lines.slice(windowStart, windowEnd).join('\n');
            if (/req\.|request\.|input\.|user\./i.test(window)) {
              nemo003Found = true;
              findings.push({
                checkId: 'NEMO-003',
                name: 'Hot-reload policy path reachable from user input',
                description: 'A policy reload mechanism is within code proximity of user input handling. An attacker could trigger policy changes through crafted requests.',
                category: 'nemo-policy',
                severity: 'high',
                passed: false,
                message: `Policy reload near user input handling at line ${i + 1}`,
                fixable: false,
                file: path.relative(targetDir, file),
                line: i + 1,
                fix: 'Gate policy reload behind operator authentication, not agent output or user requests.',
                guidance: 'User-reachable policy reload paths allow attackers to modify security policies via crafted requests. Only operators (authenticated admins) should trigger policy changes.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo003Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-003',
        name: 'Hot-reload policy paths reachable from user input',
        description: 'No policy reload paths reachable from user input found.',
        category: 'nemo-policy',
        severity: 'high',
        passed: true,
        message: 'No unsafe policy reload paths detected',
        fixable: false,
        guidance: 'User-reachable policy reload paths allow attackers to modify security policies via crafted requests, potentially disabling protections at runtime.',
      });
    }

    // ---------- NEMO-004: API key passed as CLI argument ----------
    let nemo004Found = false;
    const nemo004Files = [...cappedTsJs, ...cappedPy];
    for (const file of nemo004Files) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (
            /--credential.*\$\{.*key/i.test(line) ||
            /--api-key.*\$\{/i.test(line) ||
            /--token.*\$\{/i.test(line) ||
            /execSync.*--credential/i.test(line) ||
            /spawn.*--credential/i.test(line) ||
            /subprocess.*--credential/i.test(line)
          ) {
            nemo004Found = true;
            findings.push({
              checkId: 'NEMO-004',
              name: 'API key passed as CLI argument',
              description: 'Credentials are passed as command-line arguments to a subprocess. CLI arguments are visible in process listings (ps aux) and shell history.',
              category: 'nemo-secrets',
              severity: 'high',
              passed: false,
              message: `Credential passed as CLI argument at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Pass credentials via environment variables or stdin, not command-line arguments.',
              guidance: 'CLI arguments are visible in process listings (ps aux), shell history, and log files. Environment variables and stdin are not exposed to other processes.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo004Found && nemo004Files.length > 0) {
      findings.push({
        checkId: 'NEMO-004',
        name: 'API key passed as CLI argument',
        description: 'No credentials passed as CLI arguments detected.',
        category: 'nemo-secrets',
        severity: 'high',
        passed: true,
        message: 'No CLI credential exposure detected',
        fixable: false,
        guidance: 'CLI arguments are visible in process listings (ps aux), shell history, and log files. Environment variables and stdin keep credentials out of these surfaces.',
      });
    }

    // ---------- NEMO-005: exec() with user-controlled string interpolation ----------
    let nemo005Found = false;
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Match exec( or execSync( with template literal containing user-controlled vars
          // Exclude execFile (safe) patterns
          if (
            /\bexec(Sync)?\s*\(/.test(line) &&
            !/\bexecFile/.test(line) &&
            /`[^`]*\$\{[^}]*(name|Name|id|Id|input|arg|param|flag|option)/i.test(line)
          ) {
            nemo005Found = true;
            findings.push({
              checkId: 'NEMO-005',
              name: 'exec() with user-controlled string interpolation',
              description: 'exec() or execSync() is called with a template literal containing user-controlled variables. This enables command injection.',
              category: 'nemo-injection',
              severity: 'critical',
              passed: false,
              message: `exec() with user-controlled interpolation at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use execFile() or spawn() with array arguments instead of exec() with string interpolation.',
              guidance: 'exec() passes the entire string to /bin/sh, which interprets shell metacharacters. execFile() and spawn() with arrays bypass the shell entirely, preventing injection.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo005Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-005',
        name: 'exec() with user-controlled string interpolation',
        description: 'No exec() calls with user-controlled string interpolation found.',
        category: 'nemo-injection',
        severity: 'critical',
        passed: true,
        message: 'No command injection via exec() detected',
        fixable: false,
        guidance: 'exec() passes strings to /bin/sh, which interprets shell metacharacters. User-controlled interpolation in exec() enables arbitrary command execution.',
      });
    }

    // ---------- NEMO-006: Predictable /tmp paths without mktemp ----------
    let nemo006Found = false;
    for (const file of cappedSh) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Skip lines that ARE mktemp commands
          if (/mktemp/.test(line)) continue;
          // Match hardcoded /tmp/ writes
          if (
            /\/tmp\//.test(line) &&
            (/>/.test(line) || />>/.test(line) || /-o\s+\/tmp\//.test(line) || /install.*\/tmp\//.test(line))
          ) {
            nemo006Found = true;
            findings.push({
              checkId: 'NEMO-006',
              name: 'Predictable /tmp path without mktemp',
              description: 'A shell script writes to a hardcoded /tmp path instead of using mktemp. Predictable temp file names enable symlink attacks (CWE-377).',
              category: 'nemo-filesystem',
              severity: 'high',
              passed: false,
              message: `Hardcoded /tmp path at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'TMPDIR=$(mktemp -d) && trap "rm -rf $TMPDIR" EXIT',
              guidance: 'Hardcoded /tmp paths are predictable and enable symlink attacks (CWE-377). An attacker can pre-create a symlink at the expected path to redirect writes to sensitive files.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo006Found && cappedSh.length > 0) {
      findings.push({
        checkId: 'NEMO-006',
        name: 'Predictable /tmp paths without mktemp',
        description: 'No hardcoded /tmp paths found in shell scripts.',
        category: 'nemo-filesystem',
        severity: 'high',
        passed: true,
        message: 'No predictable temp file paths detected',
        fixable: false,
        guidance: 'Hardcoded /tmp paths are predictable and enable symlink attacks (CWE-377). An attacker can pre-create a symlink to redirect writes to sensitive files.',
      });
    }

    // ---------- NEMO-007: Full process.env passthrough to subprocess ----------
    let nemo007Found = false;
    for (const file of cappedTsJs) {
      const relForTest = path.relative(targetDir, file);
      // Test files deliberately spread process.env into subprocess setup to
      // mirror a real execution environment. This is fixture behavior, not
      // a leak. [CSR-004].
      if (isTestPath(relForTest)) continue;
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/env:\s*\{[^}]*\.\.\.process\.env/.test(line)) {
            nemo007Found = true;
            findings.push({
              checkId: 'NEMO-007',
              name: 'Full process.env passthrough to subprocess',
              description: 'process.env is spread into subprocess options, leaking all environment variables (including secrets) to child processes.',
              category: 'nemo-secrets',
              severity: 'high',
              passed: false,
              message: `Full process.env spread into subprocess at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'env: { PATH: process.env.PATH, NODE_ENV: process.env.NODE_ENV }',
              guidance: 'Spreading process.env leaks all environment variables (including API keys, tokens, database URLs) to child processes. Use an explicit allowlist of only the variables the child needs.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo007Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-007',
        name: 'Full process.env passthrough to subprocess',
        description: 'No full process.env passthrough to subprocesses found.',
        category: 'nemo-secrets',
        severity: 'high',
        passed: true,
        message: 'No process.env leakage to subprocesses detected',
        fixable: false,
        guidance: 'Spreading process.env leaks all environment variables (including API keys and tokens) to child processes. Use an explicit allowlist of only needed variables.',
      });
    }

    // ---------- NEMO-008: TOCTOU race between verify and apply ----------
    let nemo008Found = false;
    // Heuristic: look for verify/validate in one file AND exec/spawn in the same directory tree
    const dirVerifyMap = new Map<string, { verifyFile: string; verifyLine: number }>();
    const dirExecMap = new Map<string, { execFile: string; execLine: number }>();
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const dir = path.dirname(file);
        for (let i = 0; i < lines.length; i++) {
          if (/verify.*digest|validate.*hash|check.*integrity/i.test(lines[i])) {
            if (!dirVerifyMap.has(dir)) {
              dirVerifyMap.set(dir, { verifyFile: file, verifyLine: i + 1 });
            }
          }
          if (/\bspawn\s*\(|\bexec\s*\(|\bexecSync\s*\(|\bexecFile\s*\(/.test(lines[i])) {
            if (!dirExecMap.has(dir)) {
              dirExecMap.set(dir, { execFile: file, execLine: i + 1 });
            }
          }
        }
      } catch { /* skip */ }
    }
    for (const [dir, verify] of dirVerifyMap) {
      const exec = dirExecMap.get(dir);
      if (exec && verify.verifyFile !== exec.execFile) {
        nemo008Found = true;
        findings.push({
          checkId: 'NEMO-008',
          name: 'TOCTOU race between verify and apply',
          description: 'Integrity verification and execution happen in separate files, creating a time-of-check-time-of-use window where the artifact can be swapped between verification and use.',
          category: 'nemo-integrity',
          severity: 'high',
          passed: false,
          message: `Verify in ${path.relative(targetDir, verify.verifyFile)}:${verify.verifyLine}, exec in ${path.relative(targetDir, exec.execFile)}:${exec.execLine}`,
          fixable: false,
          file: path.relative(targetDir, verify.verifyFile),
          line: verify.verifyLine,
          fix: 'Copy artifact to temp dir, verify the copy, execute from the copy (atomic verify-then-execute in the same function).',
          guidance: 'When verify and execute are in separate files, an attacker can swap the artifact between verification and use (TOCTOU). Atomic verify-then-execute eliminates this race window.',
        });
      }
    }
    if (!nemo008Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-008',
        name: 'TOCTOU race between verify and apply',
        description: 'No verify/apply TOCTOU patterns detected.',
        category: 'nemo-integrity',
        severity: 'high',
        passed: true,
        message: 'No TOCTOU race conditions detected',
        fixable: false,
        guidance: 'When verify and execute are separate steps, an attacker can swap the artifact between verification and use. Atomic verify-then-execute eliminates this race window.',
      });
    }

    // ---------- NEMO-009: Unsafe deserialization of untrusted data ----------
    let nemo009Found = false;
    // Python files: pickle.load, yaml.load without SafeLoader, eval(), exec()
    for (const file of cappedPy) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/pickle\.load/i.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: pickle.load',
              description: 'pickle.load() deserializes arbitrary Python objects, enabling remote code execution if the data source is untrusted.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `pickle.load() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use json.load() or a restricted deserializer instead of pickle for untrusted data.',
              guidance: 'pickle.load() can execute arbitrary Python code during deserialization. A crafted pickle payload achieves full remote code execution.',
            });
          }
          if (/yaml\.load\s*\(/.test(line) && !/Loader\s*=\s*SafeLoader/.test(line) && !/safe_load/.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: yaml.load without SafeLoader',
              description: 'yaml.load() without SafeLoader can execute arbitrary Python code embedded in YAML documents.',
              category: 'nemo-deserialization',
              severity: 'high',
              passed: false,
              message: `yaml.load() without SafeLoader at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
              guidance: 'yaml.load() without SafeLoader can construct arbitrary Python objects, including those that execute code. SafeLoader restricts to basic data types.',
            });
          }
          if (/(?<!\.)\beval\s*\(/.test(line) || /(?<!\.)\bexec\s*\(/.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: eval/exec in Python',
              description: 'eval() or exec() executes arbitrary code. If the input originates from untrusted sources, this enables code injection.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `eval()/exec() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Replace eval/exec with ast.literal_eval() for data parsing, or use a safe DSL.',
              guidance: 'eval() and exec() execute arbitrary code. If input originates from untrusted sources (user input, network, files), this is a direct code injection vector.',
            });
          }
        }
      } catch { /* skip */ }
    }
    // TS/JS files: eval(), new Function(), JSON5.parse
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/(?<!\.)\beval\s*\(/.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: eval()',
              description: 'eval() executes arbitrary JavaScript code. If the input comes from untrusted sources, this enables code injection.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `eval() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() for data, or a sandboxed evaluator for expressions.',
              guidance: 'eval() executes arbitrary JavaScript. If the string comes from user input, network data, or files, an attacker can inject any code.',
            });
          }
          // Indirect eval: globalThis.eval(x), window.eval(x), self.eval(x), (0,eval)(x).
          // These all invoke the global eval (not a user-defined `eval` method)
          // and bypass the negative-lookbehind guard above. Detected separately
          // so the bare-eval finding above can stay narrow against method-call FPs.
          if (
            /\b(?:globalThis|window|self|frames|top|parent)\s*\.\s*eval\s*\(/.test(line) ||
            /\(\s*0\s*,\s*eval\s*\)\s*\(/.test(line)
          ) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: indirect eval()',
              description: 'Indirect eval invocations (globalThis.eval, (0,eval)(...), window.eval) call the global eval and execute arbitrary JavaScript.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `indirect eval() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() for data, or a sandboxed evaluator for expressions.',
              guidance: 'Indirect eval forms (globalThis.eval, (0,eval)) are commonly used to access the global scope; they execute arbitrary code with the same risks as bare eval().',
            });
          }
          if (/new\s+Function\s*\(/.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: new Function()',
              description: 'new Function() creates executable code from strings, equivalent to eval() for code injection risks.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `new Function() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() for data, or a sandboxed evaluator for expressions.',
              guidance: 'new Function() is equivalent to eval() -- it creates executable code from strings. If the string source is untrusted, this enables arbitrary code execution.',
            });
          }
          if (/JSON5\.parse/.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: JSON5.parse',
              description: 'JSON5.parse() is more lenient than JSON.parse(), accepting comments, trailing commas, and unquoted keys. This expanded surface can introduce parsing ambiguities.',
              category: 'nemo-deserialization',
              severity: 'high',
              passed: false,
              message: `JSON5.parse() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() instead of JSON5.parse() for untrusted data.',
              guidance: 'JSON5 accepts comments, trailing commas, and unquoted keys, expanding the parsing surface. For untrusted input, strict JSON.parse() reduces ambiguity and attack surface.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo009Found && (cappedPy.length > 0 || cappedTsJs.length > 0)) {
      findings.push({
        checkId: 'NEMO-009',
        name: 'Unsafe deserialization of untrusted data',
        description: 'No unsafe deserialization patterns detected.',
        category: 'nemo-deserialization',
        severity: 'critical',
        passed: true,
        message: 'No unsafe deserialization detected',
        fixable: false,
        guidance: 'Unsafe deserialization (pickle, eval, yaml.load) can execute arbitrary code during data parsing. A crafted payload achieves full remote code execution.',
      });
    }

    // ---------- NEMO-010: Network egress policy allows data exfiltration ----------
    let nemo010Found = false;
    const egressEndpoints = [
      'api.telegram.org',
      'discord.com/api',
      'hooks.slack.com',
      'webhook.site',
      'requestbin',
    ];
    for (const file of cappedYaml) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].toLowerCase();
          for (const endpoint of egressEndpoints) {
            if (line.includes(endpoint.toLowerCase())) {
              nemo010Found = true;
              findings.push({
                checkId: 'NEMO-010',
                name: 'Messaging API in egress policy',
                description: `Sandbox policy pre-allows access to ${endpoint}. Agents can exfiltrate data via messaging APIs without explicit operator approval.`,
                category: 'nemo-egress',
                severity: 'high',
                passed: false,
                message: `Messaging endpoint "${endpoint}" in egress policy at line ${i + 1}`,
                fixable: false,
                file: path.relative(targetDir, file),
                line: i + 1,
                fix: 'Remove messaging APIs from base sandbox policy; require explicit operator opt-in per deployment.',
                guidance: 'Pre-allowed messaging APIs (Telegram, Discord, Slack, webhook.site) enable agents to exfiltrate data without user approval. Require explicit operator opt-in per deployment.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo010Found && cappedYaml.length > 0) {
      findings.push({
        checkId: 'NEMO-010',
        name: 'Network egress policy allows data exfiltration',
        description: 'No messaging API endpoints found in egress policies.',
        category: 'nemo-egress',
        severity: 'high',
        passed: true,
        message: 'No exfiltration-prone egress endpoints detected',
        fixable: false,
        guidance: 'Pre-allowed messaging APIs (Telegram, Discord, Slack) enable agents to exfiltrate data without user approval. Require explicit operator opt-in per deployment.',
      });
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════════════
  // AI Infrastructure Exposure Checks (Research Gap Coverage)
  // These checks detect the root causes that lead to internet-exposed
  // AI services found by Shodan sweeps in the OpenA2A research program.
  // ═══════════════════════════════════════════════════════════════════

  /**
   * LLM-001 to LLM-004: Exposed LLM inference endpoints
   * Detects Ollama, vLLM, LocalAI, text-generation-webui configs bound
   * to public interfaces or missing authentication.
   */
  private async checkLLMExposure(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Patterns for LLM server configs that indicate exposure risk
    const llmConfigFiles = [
      { name: 'docker-compose.yml', altNames: ['docker-compose.yaml', 'compose.yml', 'compose.yaml'] },
      { name: 'Dockerfile', altNames: [] },
      { name: '.env', altNames: ['.env.local', '.env.production'] },
      { name: 'config.json', altNames: ['config.yaml', 'config.yml'] },
      { name: 'package.json', altNames: [] },
    ];

    const LLM_EXPOSURE_PATTERNS = [
      { id: 'LLM-001', name: 'Ollama Bound to Public Interface', service: 'Ollama',
        pattern: /OLLAMA_HOST\s*[=:]\s*["']?0\.0\.0\.0/i,
        fixPattern: /(OLLAMA_HOST\s*[=:]\s*["']?)0\.0\.0\.0/i,
        fixReplacement: '$1127.0.0.1',
        severity: 'critical' as Severity,
        description: 'Ollama server configured to listen on all interfaces. Our research found 294K+ exposed AI services on the internet — many are Ollama instances.',
        fix: 'Set OLLAMA_HOST=127.0.0.1 to restrict to localhost. If remote access is needed, use a reverse proxy with authentication.',
        guidance: 'Our research found 294K+ exposed AI services on the internet. Public Ollama instances allow anyone to run inference, steal models, or use your GPU resources.' },
      { id: 'LLM-001', name: 'Ollama Port Exposed', service: 'Ollama',
        pattern: /^(?!.*127\.0\.0\.1).*["']?11434["']?\s*:\s*["']?11434["']?/,
        fixPattern: /(["']?)11434(["']?\s*:\s*["']?11434["']?)/,
        fixReplacement: '$1127.0.0.1:11434$2',
        severity: 'high' as Severity,
        description: 'Ollama default port (11434) mapped in container config. Without bind restrictions, this exposes the inference API to the network.',
        fix: 'Map to localhost only: "127.0.0.1:11434:11434" instead of "11434:11434".',
        guidance: 'Docker port mappings without host binding expose the port on all interfaces. Prefix with 127.0.0.1: to restrict to localhost only.' },
      { id: 'LLM-002', name: 'vLLM/LocalAI Public Binding', service: 'vLLM/LocalAI',
        pattern: /--host\s+0\.0\.0\.0|host:\s*["']?0\.0\.0\.0/i,
        fixPattern: /(--host\s+|host:\s*["']?)0\.0\.0\.0/i,
        fixReplacement: '$1127.0.0.1',
        severity: 'critical' as Severity,
        description: 'LLM inference server configured to bind to all interfaces.',
        fix: 'Use --host 127.0.0.1 or bind to localhost. Use a reverse proxy with auth for remote access.',
        guidance: 'vLLM and LocalAI bound to 0.0.0.0 expose the inference API to all network interfaces. Anyone on the network can query models or abuse GPU resources.' },
      { id: 'LLM-003', name: 'Text Generation WebUI Exposed', service: 'text-generation-webui',
        pattern: /--listen\s|--share\s|GRADIO_SERVER_NAME\s*=\s*["']?0\.0\.0\.0/i,
        fixPattern: /\s*--listen\s?|\s*--share\s?|(GRADIO_SERVER_NAME\s*=\s*["']?)0\.0\.0\.0/gi,
        fixReplacement: '$1127.0.0.1',
        severity: 'high' as Severity,
        description: 'Text generation UI configured for public access with --listen or --share flag.',
        fix: 'Remove --listen and --share flags. Access via localhost or SSH tunnel.',
        guidance: '--listen binds to all interfaces and --share creates a public Gradio URL. Both expose the text generation UI to the internet without authentication.' },
      { id: 'LLM-004', name: 'OpenAI-Compatible API No Auth', service: 'OpenAI-compatible',
        pattern: /\/v1\/chat\/completions|\/v1\/completions|\/v1\/models/,
        severity: 'medium' as Severity,
        description: 'Project exposes OpenAI-compatible API endpoints. Verify authentication is enforced.',
        fix: 'Ensure API key or token authentication is required for all inference endpoints.',
        guidance: 'OpenAI-compatible API endpoints without authentication allow anyone to query your models, consume compute resources, and potentially extract training data.' },
    ];

    for (const configDef of llmConfigFiles) {
      const filesToCheck = [configDef.name, ...configDef.altNames];
      for (const filename of filesToCheck) {
        const filePath = path.join(targetDir, filename);
        try {
          let content = await fs.readFile(filePath, 'utf-8');
          if (content.length > 10 * 1024 * 1024) continue; // Skip files > 10MB
          const lines = content.split('\n');

          for (const check of LLM_EXPOSURE_PATTERNS) {
            for (let i = 0; i < lines.length; i++) {
              if (check.pattern.test(lines[i])) {
                let fixed = false;
                if (autoFix && check.fixPattern && check.fixReplacement) {
                  const original = lines[i];
                  lines[i] = lines[i].replace(check.fixPattern, check.fixReplacement);
                  if (lines[i] !== original) {
                    fixed = true;
                    content = lines.join('\n');
                    await fs.writeFile(filePath, content);
                  }
                }

                findings.push({
                  checkId: check.id,
                  name: check.name,
                  description: check.description,
                  category: 'llm-exposure',
                  severity: check.severity,
                  passed: fixed,
                  message: `${check.service} exposure detected in ${filename}`,
                  file: filename,
                  line: i + 1,
                  fixable: !!check.fixPattern,
                  fixed,
                  fix: check.fix,
                  guidance: (check as Record<string, unknown>).guidance as string | undefined,
                });
                break; // One finding per pattern per file
              }
            }
          }
        } catch {
          // File doesn't exist, skip
        }
      }
    }

    return findings;
  }

  /**
   * AITOOL-001 to AITOOL-004: Exposed AI development tooling
   * Detects Jupyter, Gradio, Streamlit, MLflow, LangServe configs
   * that are publicly accessible.
   */
  private async checkAIToolExposure(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Fix transforms for AI tool patterns
    const AI_TOOL_FIXES: Record<string, Array<{ match: RegExp; replace: string }>> = {
      'AITOOL-001': [
        { match: /(NotebookApp\.token\s*=\s*)['"]{2}/, replace: `$1'${crypto.randomBytes(32).toString('hex')}'` },
        { match: /(NotebookApp\.password\s*=\s*)['"]{2}/, replace: `$1'${crypto.randomBytes(32).toString('hex')}'` },
        { match: /(ServerApp\.token\s*=\s*)['"]{2}/, replace: `$1'${crypto.randomBytes(32).toString('hex')}'` },
        { match: /(--ip\s*=?\s*["']?)0\.0\.0\.0/, replace: '$1127.0.0.1' },
        { match: /--NotebookApp\.token=['"]?\s/, replace: `--NotebookApp.token=${crypto.randomBytes(32).toString('hex')} ` },
      ],
      'AITOOL-002': [
        { match: /(share\s*=\s*)True/, replace: '$1False' },
        { match: /(GRADIO_SERVER_NAME\s*=\s*["']?)0\.0\.0\.0/, replace: '$1127.0.0.1' },
        { match: /(server\.address\s*=\s*["']?)0\.0\.0\.0/, replace: '$1127.0.0.1' },
      ],
      'AITOOL-003': [
        { match: /(--host\s+)0\.0\.0\.0/i, replace: '$1127.0.0.1' },
      ],
    };

    const AI_TOOL_PATTERNS: Array<{
      id: string; name: string; severity: Severity; description: string; fix: string;
      guidance: string; filePatterns: string[]; contentPatterns: RegExp[];
    }> = [
      {
        id: 'AITOOL-001', name: 'Jupyter Notebook Publicly Accessible',
        severity: 'critical',
        description: 'Jupyter notebook server configured without authentication or bound to public interface. Our research found exposed Jupyter instances with full code execution on the internet.',
        fix: 'Set c.NotebookApp.token or c.NotebookApp.password. Bind to 127.0.0.1. Never use --NotebookApp.token=\'\' in production.',
        guidance: 'Jupyter notebooks allow arbitrary code execution. A publicly accessible instance with no auth gives attackers full shell access on the host machine.',
        filePatterns: ['jupyter_notebook_config.py', 'jupyter_server_config.py', 'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile'],
        contentPatterns: [
          /NotebookApp\.token\s*=\s*['"]{2}/,          // Empty token
          /NotebookApp\.password\s*=\s*['"]{2}/,        // Empty password
          /--NotebookApp\.token=['"]{0,2}\s/,            // CLI empty token
          /--ip\s*=?\s*["']?0\.0\.0\.0/,                 // Bind all interfaces
          /ServerApp\.token\s*=\s*['"]{2}/,              // Jupyter Server empty token
        ],
      },
      {
        id: 'AITOOL-002', name: 'Gradio/Streamlit Public Sharing',
        severity: 'high',
        description: 'ML demo framework configured for public access. Gradio share links and public Streamlit deployments can expose model inference and data pipelines.',
        fix: 'Remove share=True from Gradio launch(). For Streamlit, add authentication or use private deployment.',
        guidance: 'Gradio share links create public URLs that bypass network security. Streamlit on 0.0.0.0 exposes the app to the internet. Both can leak model inference and data pipelines.',
        filePatterns: ['*.py', 'app.py', 'main.py', 'streamlit_app.py', 'demo.py'],
        contentPatterns: [
          /\.launch\s*\([^)]*share\s*=\s*True/,                // Gradio share=True
          /GRADIO_SERVER_NAME\s*=\s*["']?0\.0\.0\.0/,          // Gradio bind all
          /server\.address\s*=\s*["']?0\.0\.0\.0/,             // Streamlit bind all
        ],
      },
      {
        id: 'AITOOL-003', name: 'MLflow Tracking Server No Auth',
        severity: 'high',
        description: 'MLflow tracking server configured without authentication. Exposed MLflow instances leak experiment data, model artifacts, and parameters.',
        fix: 'Configure MLflow with --backend-store-uri and authentication. Use a reverse proxy with auth for remote access.',
        guidance: 'Exposed MLflow instances leak experiment data, model artifacts, hyperparameters, and metrics. Add authentication before exposing to any network.',
        filePatterns: ['docker-compose.yml', 'docker-compose.yaml', 'Dockerfile', 'Makefile', '*.sh'],
        contentPatterns: [
          /mlflow\s+server\s+.*--host\s+0\.0\.0\.0/i,
          /mlflow\s+ui\s+.*--host\s+0\.0\.0\.0/i,
          /MLFLOW_TRACKING_URI\s*=\s*["']?http:\/\//,
        ],
      },
      {
        id: 'AITOOL-004', name: 'LangServe Endpoint Exposed',
        severity: 'high',
        description: 'LangChain LangServe endpoint configured for public access. Exposed LangServe instances allow arbitrary chain invocation.',
        fix: 'Add authentication middleware to LangServe routes. Bind to 127.0.0.1 for local-only access.',
        guidance: 'LangServe exposes LangChain chains as REST endpoints. Without auth, anyone can invoke arbitrary chain operations, potentially accessing sensitive data or incurring costs.',
        filePatterns: ['*.py', 'app.py', 'main.py', 'server.py'],
        contentPatterns: [
          /add_routes\s*\(/,                                    // LangServe route
          /from\s+langserve\s+import/,                          // LangServe import
        ],
      },
    ];

    for (const check of AI_TOOL_PATTERNS) {
      const fixTransforms = AI_TOOL_FIXES[check.id];
      const isFixable = !!fixTransforms;

      for (const filePattern of check.filePatterns) {
        const filesToCheck: string[] = [];

        if (filePattern.includes('*')) {
          try {
            const entries = await fs.readdir(targetDir, { withFileTypes: true });
            const ext = filePattern.replace('*', '');
            for (const entry of entries) {
              if (entry.isFile() && entry.name.endsWith(ext)) {
                filesToCheck.push(entry.name);
              }
            }
          } catch { /* skip */ }
        } else {
          filesToCheck.push(filePattern);
        }

        for (const filename of filesToCheck) {
          const filePath = path.join(targetDir, filename);
          try {
            let content = await fs.readFile(filePath, 'utf-8');
            if (content.length > 10 * 1024 * 1024) continue;
            const lines = content.split('\n');

            for (const pattern of check.contentPatterns) {
              for (let i = 0; i < lines.length; i++) {
                pattern.lastIndex = 0;
                if (pattern.test(lines[i])) {
                  if (check.id === 'AITOOL-004' && /from\s+langserve/.test(lines[i])) {
                    const hasRoutes = content.includes('add_routes');
                    const hasBind = /0\.0\.0\.0/.test(content);
                    if (!hasRoutes || !hasBind) continue;
                  }

                  let fixed = false;
                  if (autoFix && fixTransforms) {
                    for (const ft of fixTransforms) {
                      if (ft.match.test(lines[i])) {
                        lines[i] = lines[i].replace(ft.match, ft.replace);
                        fixed = true;
                      }
                    }
                    if (fixed) {
                      content = lines.join('\n');
                      await fs.writeFile(filePath, content);
                    }
                  }

                  findings.push({
                    checkId: check.id,
                    name: check.name,
                    description: check.description,
                    category: 'ai-tool-exposure',
                    severity: check.severity,
                    passed: fixed,
                    message: `${check.name} in ${filename}`,
                    file: filename,
                    line: i + 1,
                    fixable: isFixable,
                    fixed,
                    fix: check.fix,
                    guidance: check.guidance,
                  });
                  break;
                }
              }
            }
          } catch { /* file doesn't exist, skip */ }
        }
      }
    }

    return findings;
  }

  /**
   * A2A-001 to A2A-002: A2A protocol exposure
   * Detects .well-known/agent.json and task submission endpoints
   * that are publicly accessible without authentication.
   */
  private async checkA2AExposure(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Check for .well-known/agent.json (A2A discovery file)
    const wellKnownPaths = [
      path.join(targetDir, '.well-known', 'agent.json'),
      path.join(targetDir, 'public', '.well-known', 'agent.json'),
      path.join(targetDir, 'static', '.well-known', 'agent.json'),
    ];

    for (const agentJsonPath of wellKnownPaths) {
      try {
        const content = await fs.readFile(agentJsonPath, 'utf-8');
        const relativePath = path.relative(targetDir, agentJsonPath);

        // Parse and check for sensitive capabilities
        let agentCard: Record<string, unknown> = {};
        try { agentCard = JSON.parse(content); } catch { /* invalid JSON, still flag it */ }

        const hasAuth = content.includes('"authentication"') || content.includes('"auth"');

        findings.push({
          checkId: 'A2A-001',
          name: 'A2A Agent Discovery File Exposed',
          description: 'A .well-known/agent.json file makes this agent discoverable via the A2A protocol. Our research found exposed agent.json files that allow unauthenticated task submission.',
          category: 'a2a-exposure',
          severity: hasAuth ? 'medium' : 'high',
          passed: false,
          message: hasAuth
            ? 'Agent card found with authentication configured'
            : 'Agent card found WITHOUT authentication — any client can submit tasks',
          file: relativePath,
          fixable: false,
          fix: 'Add authentication requirements to your agent card. Restrict task submission to authenticated clients.',
          guidance: 'A2A agent cards make your agent discoverable on the network. Without authentication requirements, any client can submit tasks and consume resources or access sensitive data.',
          details: { hasAuth, capabilities: agentCard.capabilities },
        });
        break; // Found one, no need to check other paths
      } catch { /* doesn't exist */ }
    }

    // Check source files for A2A task endpoints without auth middleware
    const sourceFiles = ['server.py', 'app.py', 'main.py', 'server.ts', 'app.ts', 'index.ts'];
    for (const filename of sourceFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, filename), 'utf-8');
        if (content.length > 10 * 1024 * 1024) continue;

        const hasTaskEndpoint = /\/tasks\/send|\/tasks\/get|\/tasks\/cancel/.test(content);
        const hasAuthMiddleware = /auth|authenticate|verify.*token|api.?key|bearer/i.test(content);

        if (hasTaskEndpoint && !hasAuthMiddleware) {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (/\/tasks\/send|\/tasks\/get/.test(lines[i])) {
              findings.push({
                checkId: 'A2A-002',
                name: 'A2A Task Endpoint Without Authentication',
                description: 'A2A task submission endpoint found without visible authentication middleware.',
                category: 'a2a-exposure',
                severity: 'high',
                passed: false,
                message: `Unauthenticated task endpoint in ${filename}`,
                file: filename,
                line: i + 1,
                fixable: false,
                fix: 'Add authentication middleware to /tasks/send and /tasks/get endpoints. Require API key or bearer token.',
                guidance: 'Unauthenticated A2A task endpoints allow anyone to submit tasks to your agent. This can lead to resource abuse, data exfiltration, or unauthorized actions.',
              });
              break;
            }
          }
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * MCP-011: MCP discovery endpoint exposure
   * Detects .well-known/mcp files that make MCP servers discoverable.
   */
  private async checkMCPDiscovery(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    const mcpDiscoveryPaths = [
      path.join(targetDir, '.well-known', 'mcp'),
      path.join(targetDir, '.well-known', 'mcp.json'),
      path.join(targetDir, 'public', '.well-known', 'mcp'),
      path.join(targetDir, 'public', '.well-known', 'mcp.json'),
      path.join(targetDir, 'static', '.well-known', 'mcp'),
      path.join(targetDir, 'static', '.well-known', 'mcp.json'),
    ];

    for (const mcpPath of mcpDiscoveryPaths) {
      try {
        const content = await fs.readFile(mcpPath, 'utf-8');
        const relativePath = path.relative(targetDir, mcpPath);

        const hasCredentials = CREDENTIAL_PATTERNS.some(({ pattern }) => {
          pattern.lastIndex = 0;
          return pattern.test(content);
        });

        findings.push({
          checkId: 'MCP-011',
          name: 'MCP Discovery Endpoint Exposed',
          description: 'A .well-known/mcp discovery file makes MCP servers publicly discoverable. Our research found exposed MCP endpoints via this mechanism.',
          category: 'mcp',
          severity: hasCredentials ? 'critical' : 'high',
          passed: false,
          message: hasCredentials
            ? 'MCP discovery file contains credentials — CRITICAL exposure'
            : 'MCP discovery file found — servers are publicly discoverable',
          file: relativePath,
          fixable: false,
          fix: 'Remove .well-known/mcp from public-facing directories, or restrict access via web server configuration. Never include credentials in discovery files.',
          guidance: 'MCP discovery files make servers publicly discoverable. If they contain credentials, those are exposed to anyone who requests the URL. Restrict access or remove from public directories.',
        });
        break;
      } catch { /* doesn't exist */ }
    }

    return findings;
  }

  /**
   * WEBCRED-001 to WEBCRED-002: Credentials in web-served files
   * Detects API keys in HTML, JS, and other files typically served
   * by web servers. Distinct from CRED-001 which checks config files.
   */
  private async checkWebServedCredentials(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Unambiguous web-served directories — static assets published to a
    // public web server.
    const unambiguousWebDirs = ['public', 'static', 'www', '_site'];
    // Ambiguous directories — commonly Node.js / TypeScript compile output
    // (tsc, rollup, esbuild server bundles), but also frequently browser
    // bundles from frontend frameworks. Treat as web-served only when at
    // least one of these signals holds:
    //   - The directory contains ANY `.html` file (not just `index.html` —
    //     browser apps may ship only `home.html` or per-route pages).
    //   - The project's `package.json` declares a `browser` field or
    //     `main`/`module`/`exports` that points into this directory while
    //     also declaring a `browser` entry (npm browser-library convention).
    // Otherwise this is Node.js compile output — skip to avoid flagging the
    // package's own credential-detection regex source as exposed creds.
    const ambiguousWebDirs = ['dist', 'build', 'out', '.next', '.nuxt', 'target'];
    const webFileExts = ['.html', '.htm', '.js', '.jsx', '.tsx', '.css', '.svg'];

    // Load package.json browser-signal once.
    let pkgDeclaresBrowser = false;
    let pkgBrowserDirs: Set<string> = new Set();
    try {
      const pkgRaw = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      const pkg = JSON.parse(pkgRaw);
      if (pkg && (pkg.browser !== undefined || pkg.unpkg !== undefined || pkg.jsdelivr !== undefined)) {
        pkgDeclaresBrowser = true;
        // Collect directories referenced by browser/unpkg/jsdelivr.
        // Skip leading ./ and ../ segments — idiomatic package.json entries
        // like "./dist/bundle.js" should record `dist`, not `.`.
        const collect = (v: unknown) => {
          if (typeof v === 'string') {
            const segs = v.split('/').filter(s => s && s !== '.' && s !== '..');
            if (segs[0]) pkgBrowserDirs.add(segs[0]);
          } else if (v && typeof v === 'object') {
            for (const inner of Object.values(v as Record<string, unknown>)) collect(inner);
          }
        };
        collect(pkg.browser);
        collect(pkg.unpkg);
        collect(pkg.jsdelivr);
      }
    } catch {
      // No package.json or unparseable — fall back to .html signal only.
    }

    // Project-level web-framework signal: many SPAs ship JS bundles in dist/
    // while serving index.html from a separate origin (nginx/Express). Such
    // projects do NOT declare `browser` in package.json and have no .html
    // inside dist/, but the bundle is still client-visible. Detect frontend
    // build-tool config files at the project root as a third signal.
    let isFrontendProject = false;
    try {
      const rootEntries = await fs.readdir(targetDir);
      const frontendConfigs = [
        'vite.config.js', 'vite.config.ts', 'vite.config.mjs',
        'webpack.config.js', 'webpack.config.ts',
        'rollup.config.js', 'rollup.config.ts', 'rollup.config.mjs',
        'next.config.js', 'next.config.ts', 'next.config.mjs',
        'nuxt.config.js', 'nuxt.config.ts',
        'svelte.config.js', 'svelte.config.ts',
        'astro.config.mjs', 'astro.config.ts', 'astro.config.js',
        'remix.config.js', 'gatsby-config.js', 'gatsby-config.ts',
        'parcel.config.js', 'esbuild.config.js',
        'angular.json', 'vue.config.js', 'vue.config.ts',
        'index.html',
      ];
      isFrontendProject = rootEntries.some(e => frontendConfigs.includes(e));
    } catch {
      // No targetDir read — skip the signal.
    }

    const allWebDirs: string[] = [...unambiguousWebDirs];
    for (const dir of ambiguousWebDirs) {
      const dirPath = path.join(targetDir, dir);
      try {
        await fs.access(dirPath);
      } catch {
        continue;
      }
      // Signal 1: any .html file anywhere in the dir tree. A browser bundle
      // ships at least one .html shell; a tsc compile output does not.
      const htmlFiles = await this.findWebFiles(dirPath, ['.html', '.htm'], 0, dirPath);
      if (htmlFiles.length > 0) {
        allWebDirs.push(dir);
        continue;
      }
      // Signal 2: package.json declares browser/unpkg/jsdelivr entries that
      // reference this directory (npm browser-library convention). This
      // covers libraries like `@foo/widget` that ship `dist/widget.umd.js`
      // without an HTML shell — the package.json tells consumers (and us)
      // that the bundle is meant for the browser.
      if (pkgDeclaresBrowser && pkgBrowserDirs.has(dir)) {
        allWebDirs.push(dir);
        continue;
      }
      // Signal 3: project root carries a frontend-build config (vite,
      // webpack, next, rollup, nuxt, svelte, astro, etc.) or a top-level
      // index.html. SPAs that serve index.html externally still ship
      // client-visible bundles from dist/ — the signature is the build
      // tool, not the bundle layout.
      if (isFrontendProject) {
        allWebDirs.push(dir);
        continue;
      }
    }

    for (const webDir of allWebDirs) {
      const dirPath = path.join(targetDir, webDir);
      try {
        await fs.access(dirPath);
      } catch {
        continue; // Directory doesn't exist
      }

      // Recursively scan web-served directory (max depth 3)
      const webFiles = await this.findWebFiles(dirPath, webFileExts, 0, dirPath);

      for (const filePath of webFiles) {
        try {
          let content = await fs.readFile(filePath, 'utf-8');
          if (content.length > 10 * 1024 * 1024) continue;
          let lines = content.split('\n');
          const relativePath = path.relative(targetDir, filePath);
          let fileModified = false;

          for (const { name, pattern } of CREDENTIAL_PATTERNS) {
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].length > 10000) continue;
              pattern.lastIndex = 0;
              if (pattern.test(lines[i])) {
                let fixed = false;

                if (autoFix) {
                  // Replace credential with process.env reference
                  // Also strip surrounding quotes so `"sk-proj-..."` becomes `process.env.VAR` not `"process.env.VAR"`
                  const envVar = name.replace(/\s+/g, '_').toUpperCase();
                  pattern.lastIndex = 0;
                  const original = lines[i];
                  const envRef = `process.env.${envVar}`;
                  // Replace quoted credential: "sk-..." or 'sk-...' → process.env.VAR (no quotes)
                  const quotedPattern = new RegExp(`(['"])${pattern.source}\\1`, pattern.flags);
                  quotedPattern.lastIndex = 0;
                  if (quotedPattern.test(lines[i])) {
                    quotedPattern.lastIndex = 0;
                    lines[i] = lines[i].replace(quotedPattern, envRef);
                  } else {
                    // No quotes, just replace the credential directly
                    pattern.lastIndex = 0;
                    lines[i] = lines[i].replace(pattern, envRef);
                  }
                  if (lines[i] !== original) {
                    fixed = true;
                    fileModified = true;
                  }
                }

                findings.push({
                  checkId: 'WEBCRED-001',
                  name: 'Credential in Web-Served File',
                  description: `${name} found in a file within a web-served directory. This credential is likely accessible to anyone who visits the site. Our research found API keys exposed in HTML source on the public internet.`,
                  category: 'web-credentials',
                  severity: 'critical',
                  passed: fixed,
                  message: fixed
                    ? `${name} in ${relativePath} replaced with environment variable reference`
                    : `${name} exposed in ${relativePath}`,
                  file: relativePath,
                  line: i + 1,
                  fixable: true,
                  fixed,
                  fix: `opena2a protect .  — scans for hardcoded secrets and encrypts them into a secure vault. Never include API keys in client-side code — use a backend proxy for API calls.`,
                  guidance: 'Credentials in web-served files (HTML, JS, CSS) are visible to anyone who views the page source. API keys in client-side code can be extracted and abused for unauthorized access.',
                });
                break;
              }
            }
          }

          if (fileModified) {
            content = lines.join('\n');
            await fs.writeFile(filePath, content);
          }
        } catch { /* skip unreadable files */ }
      }
    }

    return findings;
  }

  /**
   * CODEINJ-001: exec() with template literal interpolation
   * Detects shell injection via exec/execSync called with template literals.
   */
  private async checkCodeInjection(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.ts', '.js', '.mjs'], 0, 2);

    // Match exec( or execSync( followed by a backtick (template literal)
    // Do NOT match execFile or execFileSync (those use array args, safe)
    const pattern = /\b(?<!File)exec(?:Sync)?\s*\(\s*`/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'CODEINJ-001',
              name: 'exec() with template literal interpolation',
              description: 'exec() or execSync() called with a template literal allows shell injection. User-controlled values in the template can break out of the intended command.',
              category: 'code-injection',
              severity: 'critical',
              passed: false,
              message: `Shell injection risk: exec() with template literal in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Use execFile() or execFileSync() with an array of arguments instead of exec() with string interpolation.',
              guidance: 'Template literals in exec() are interpreted by /bin/sh, allowing shell metacharacters in interpolated values to execute arbitrary commands. Array-based APIs bypass the shell.',
            });
            break; // One finding per file
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * INSTALL-001: curl|sh without checksum in shell scripts
   * Detects piped-to-shell install patterns in .sh files.
   */
  private async checkInstallScripts(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.sh'], 0, 2);

    const pattern = /\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'INSTALL-001',
              name: 'curl|sh without checksum verification',
              description: 'Shell script downloads and executes code via curl|sh or wget|sh without verifying a checksum. A MITM or compromised server can inject arbitrary code.',
              category: 'supply-chain',
              severity: 'critical',
              passed: false,
              message: `Unsafe pipe-to-shell install in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Download the script to a file first, verify its checksum (sha256sum), then execute it.',
              guidance: 'Piping directly to sh executes whatever the remote server returns without verification. A compromised or MITM-ed server can inject arbitrary code into your system.',
            });
            break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * CLIPASS-001: Credentials passed as CLI arguments
   * Detects --token, --password, --api-key, --secret followed by variable interpolation.
   */
  private async checkCLICredentialPassthrough(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.ts', '.js', '.mjs'], 0, 2);

    const pattern = /--(token|password|api[_-]?key|secret|auth)\s*[=\s]\s*[`$"']\s*\$?\{?|["']--(token|password|api[_-]?key|secret|auth)["']/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            // Verify it's in a spawn/exec context
            const contextStart = Math.max(0, i - 5);
            const context = lines.slice(contextStart, i + 1).join('\n');
            if (/\b(exec\w*|spawn\w*|fork|run)\b/i.test(context)) {
              findings.push({
                checkId: 'CLIPASS-001',
                name: 'Credentials passed as CLI arguments',
                description: 'Credentials are passed as command-line arguments (--token, --password, etc.) with variable interpolation. CLI args are visible in process listings (ps aux) and shell history.',
                category: 'credential-exposure',
                severity: 'high',
                passed: false,
                message: `Credentials passed as CLI arguments in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Pass credentials via environment variables, stdin, or a config file instead of CLI arguments.',
                guidance: 'CLI arguments are visible to all users via ps aux, logged in shell history, and often captured in audit logs. Environment variables and stdin are not exposed to other processes.',
              });
              break;
            }
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * INTEGRITY-001: Digest/hash verification bypass on falsy value
   * Detects patterns like `if (digest &&` or `if (hash &&` where empty value skips check.
   */
  private async checkIntegrityBypass(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.ts', '.js', '.mjs'], 0, 2);

    const pattern = /if\s*\(\s*(digest|hash|checksum|signature|integrity)\s*&&/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'INTEGRITY-001',
              name: 'Integrity check bypass on falsy value',
              description: 'Integrity verification (digest/hash/checksum) is guarded by a truthiness check. If the value is empty, undefined, or null, the entire integrity check is silently skipped.',
              category: 'integrity-bypass',
              severity: 'critical',
              passed: false,
              message: `Integrity check bypass risk in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Require the integrity value to be present. Throw an error if digest/hash is missing rather than skipping verification.',
              guidance: 'A truthiness check on digest/hash silently skips verification when the value is empty. An attacker can remove the digest from a manifest to bypass all integrity checks.',
            });
            break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * TOCTOU-001: Verify then use without atomic operation
   * Detects files that verify and then execute on the same path without atomicity.
   */
  private async checkTOCTOU(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.ts', '.js', '.mjs'], 0, 2);

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const relativePath = path.relative(targetDir, file);

        // Test files deliberately exercise check-then-use shapes (including
        // intentional TOCTOU demonstrations and file-IO exercisers). Skip
        // them — shape-based TOCTOU detection cannot distinguish fixture
        // from production. [CSR-004].
        if (isTestPath(relativePath)) continue;

        // Two-tier TOCTOU detection, 40-line proximity window (same function scope):
        //
        //  Tier A — Access-gate TOCTOU: existsSync/accessSync/access() on a variable,
        //    then any READ or EXEC use of the same variable. The access gate is the
        //    classic TOCTOU pattern — the check blesses the path, the use trusts it.
        //
        //  Tier B — Stat-then-exec TOCTOU: statSync/lstatSync/fs.stat/fs.lstat on a
        //    variable, then EXEC use (execFile/spawn/execSync) of the same variable.
        //    Stat-then-read alone is tolerated: content scanners legitimately stat
        //    for size filtering then read for analysis with no trust transfer.
        const fileLines = content.split('\n');

        const accessGatePattern = /\b(?:existsSync|accessSync|fs\.access)\s*\(\s*(\w+)\s*[,)]/g;
        const statPattern = /\b(?:statSync|lstatSync|fs\.stat|fs\.lstat)\s*\(\s*(\w+)\s*[,)]/g;
        const readUseRe = (v: string) => new RegExp(
          `\\b(?:readFile(?:Sync)?|createReadStream|open(?:Sync)?|execFile(?:Sync)?|spawn(?:Sync)?|execSync)\\s*\\(\\s*${v}\\b`
        );
        const execUseRe = (v: string) => new RegExp(
          `\\b(?:execFile(?:Sync)?|spawn(?:Sync)?|execSync|child_process\\.exec)\\s*\\(\\s*${v}\\b`
        );
        const windowHasUse = (checkLineIdx: number, re: RegExp): boolean => {
          const windowEnd = Math.min(checkLineIdx + 40, fileLines.length);
          for (let i = checkLineIdx; i < windowEnd; i++) {
            if (re.test(fileLines[i])) return true;
          }
          return false;
        };

        const accessGateHit = [...content.matchAll(accessGatePattern)].some(m => {
          const varName = m[1];
          const lineIdx = content.slice(0, m.index!).split('\n').length - 1;
          return windowHasUse(lineIdx, readUseRe(varName));
        });
        const statExecHit = [...content.matchAll(statPattern)].some(m => {
          const varName = m[1];
          const lineIdx = content.slice(0, m.index!).split('\n').length - 1;
          return windowHasUse(lineIdx, execUseRe(varName));
        });
        const readAfterCheck = accessGateHit || statExecHit;
        // Pattern 2: integrity verify (hash/signature) followed by exec/spawn on the same path.
        const hasIntegrityVerify = /\b(verify|validate)(Hash|Signature|Digest|Checksum|Integrity)\s*\(/i.test(content);
        const hasShellExec = /\b(execFile|spawnSync|execSync|child_process)\s*\(/i.test(content);
        const hasFilePath = /\b(filePath|targetPath|scriptPath|modulePath)\b/.test(content);

        if (readAfterCheck || (hasIntegrityVerify && hasShellExec && hasFilePath)) {
          {
            // Find the line with the check for reporting
            let verifyLine = 0;
            const verifyPattern = /\b(?:existsSync|accessSync)\s*\(|\b(?:verify|validate)(?:Hash|Signature|Digest|Checksum|Integrity)\s*\(/i;
            for (let i = 0; i < fileLines.length; i++) {
              if (verifyPattern.test(fileLines[i])) {
                verifyLine = i + 1;
                break;
              }
            }
            findings.push({
              checkId: 'TOCTOU-001',
              name: 'Time-of-check-time-of-use race condition',
              description: 'File is verified (checksum/signature) and then used (executed/loaded) in separate operations without file locking. An attacker can replace the file between verify and use.',
              category: 'toctou-race',
              severity: 'high',
              passed: false,
              message: `TOCTOU risk: verify-then-use without atomic operation in ${relativePath}`,
              file: relativePath,
              line: verifyLine,
              fixable: false,
              fix: 'Use atomic file operations: verify and load in a single locked operation, or copy to a temp location before verification.',
              guidance: 'TOCTOU races allow file replacement between verification and use. An attacker can swap a verified file with a malicious one in the time window between the two operations.',
            });
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * TMPPATH-001: Hardcoded /tmp paths without mktemp
   * Detects writes to /tmp/ with hardcoded paths in shell scripts.
   */
  private async checkTmpPaths(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.sh'], 0, 2);

    const pattern = /(>|>>)\s*\/tmp\/|(-o)\s+\/tmp\/|\s\/tmp\/\S+/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        // Only flag if the script does NOT actually use mktemp (ignore comments)
        const nonCommentLines = lines.filter(l => !l.trimStart().startsWith('#'));
        if (/\bmktemp\b/.test(nonCommentLines.join('\n'))) continue;

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'TMPPATH-001',
              name: 'Hardcoded /tmp path without mktemp',
              description: 'Shell script writes to a hardcoded /tmp/ path. Another user or process can create a symlink at that path to redirect writes (symlink attack).',
              category: 'tmppath-attack',
              severity: 'high',
              passed: false,
              message: `Hardcoded /tmp path in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Use mktemp to create a unique temporary file/directory instead of hardcoded /tmp paths.',
              guidance: 'Predictable /tmp paths enable symlink attacks (CWE-377). Another user can create a symlink at the expected path, redirecting writes to sensitive files like /etc/passwd.',
            });
            break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * DOCKERINJ-001: Docker exec with variable interpolation
   * Detects docker exec commands with unquoted variable expansion.
   */
  private async checkDockerInjection(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.sh'], 0, 2);

    const pattern = /docker\s+exec\b.*?(\$\{?\w+\}?)/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          const line = lines[i];
          // Detect docker exec with any variable interpolation (quoted or not)
          if (/docker\s+exec\b/.test(line) && /\$\{?\w+\}?/.test(line)) {
              findings.push({
                checkId: 'DOCKERINJ-001',
                name: 'Docker exec with variable interpolation',
                description: 'docker exec command uses shell variable expansion. An attacker who controls the variable value can inject additional docker commands or escape the container context, even when quoted (e.g., in bash -c contexts).',
                category: 'code-injection',
                severity: 'high',
                passed: false,
                message: `Variable interpolation in docker exec in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Avoid passing user-controlled variables to docker exec. Validate and sanitize all inputs, and avoid bash -c with interpolated variables.',
                guidance: 'Variable interpolation in docker exec allows command injection. If the variable contains shell metacharacters, an attacker can execute arbitrary commands inside or escape the container.',
              });
              break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * ENVLEAK-001: process.env spread to child process
   * Detects passing all environment variables (including secrets) to child processes.
   */
  private async checkEnvLeak(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.ts', '.js', '.mjs'], 0, 2);

    const spreadPattern = /env:\s*\{\s*\.\.\.process\.env/g;
    const directPattern = /\benv:\s*process\.env\b/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          spreadPattern.lastIndex = 0;
          directPattern.lastIndex = 0;
          if (spreadPattern.test(lines[i]) || directPattern.test(lines[i])) {
            // Verify it's in a spawn/exec context
            const contextStart = Math.max(0, i - 5);
            const context = lines.slice(contextStart, i + 3).join('\n');
            if (/\b(spawn|exec|fork|execFile|execSync|spawnSync)\b/.test(context)) {
              findings.push({
                checkId: 'ENVLEAK-001',
                name: 'process.env spread to child process',
                description: 'All environment variables (including secrets like API keys, database passwords) are passed to a child process via env: process.env or { ...process.env }.',
                category: 'env-leak',
                severity: 'high',
                passed: false,
                message: `Full environment leaked to child process in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Pass only the specific environment variables the child process needs: env: { PATH: process.env.PATH, NODE_ENV: process.env.NODE_ENV }.',
                guidance: 'Spreading process.env passes all secrets (API keys, DB passwords, tokens) to child processes. A compromised or malicious child can read and exfiltrate these credentials.',
              });
              break;
            }
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * SANDBOX-005: Messaging API pre-allowed in sandbox policy
   * Detects pre-allowed URLs for messaging services in sandbox policies.
   */
  private async checkSandboxMessaging(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Scan YAML/JSON files in policies/ and config/ directories
    const policyDirs = ['policies', 'config', '.openclaw'];
    const policyExts = ['.yml', '.yaml', '.json'];

    for (const dirName of policyDirs) {
      const dirPath = path.join(targetDir, dirName);
      try {
        await fs.access(dirPath);
      } catch {
        continue;
      }

      const files = await this.walkDirectory(dirPath, policyExts, 0, 2);
      const messagingPattern = /\b(telegram|slack|discord|webhook\.site|requestbin|pipedream)\b/gi;

      for (const file of files.slice(0, 50)) {
        try {
          const stat = await fs.stat(file);
          if (stat.size > MAX_FILE_SIZE) continue;
          const content = await fs.readFile(file, 'utf-8');
          const lines = content.split('\n');
          const relativePath = path.relative(targetDir, file);

          for (let i = 0; i < lines.length; i++) {
            if (lines[i].length > MAX_LINE_LENGTH) continue;
            messagingPattern.lastIndex = 0;
            const match = messagingPattern.exec(lines[i]);
            if (match) {
              // Check if this is in an allow/whitelist context
              const contextStart = Math.max(0, i - 3);
              const context = lines.slice(contextStart, i + 1).join('\n').toLowerCase();
              if (/\b(allow\w*|whitelist\w*|permit\w*|pre[_-]?allow\w*|approved|trusted)\b/.test(context)) {
                findings.push({
                  checkId: 'SANDBOX-005',
                  name: 'Messaging API pre-allowed in sandbox policy',
                  description: `Messaging service (${match[1]}) is pre-allowed in sandbox policy. An attacker who gains code execution inside the sandbox can exfiltrate data via this channel without triggering additional permission prompts.`,
                  category: 'sandbox-escape',
                  severity: 'high',
                  passed: false,
                  message: `Messaging API (${match[1]}) pre-allowed in ${relativePath}`,
                  file: relativePath,
                  line: i + 1,
                  fixable: false,
                  fix: 'Remove messaging services from pre-allowed URLs. Require explicit user approval for outbound messaging.',
                  guidance: 'Pre-allowed messaging APIs let sandbox code exfiltrate data silently via Telegram, Slack, or Discord without triggering permission prompts. Require explicit approval for each outbound message.',
                });
                break;
              }
            }
          }
        } catch { /* skip unreadable files */ }
      }
    }

    return findings;
  }

  /**
   * WEBEXPOSE-001: CLAUDE.md in web-served directories
   * WEBEXPOSE-002: .env files in web-served directories
   * WEBEXPOSE-003: Sensitive config files in web-served directories
   */
  private async checkWebExposedFiles(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    const webDirs = ['public', 'static', 'dist', 'build', 'out', 'www'];
    // Track seen real paths to avoid duplicates on case-insensitive filesystems
    const seenPaths = new Set<string>();

    // WEBEXPOSE-001: CLAUDE.md in web directories
    const claudeFiles = ['CLAUDE.md', 'claude.md'];
    // WEBEXPOSE-002: .env files in web directories
    const envFiles = ['.env', '.env.local', '.env.production'];
    // WEBEXPOSE-003: Sensitive config files in web directories
    const configFiles = ['mcp.json', 'config.json', 'settings.json', 'openclaw.json'];
    const configDirs = ['.claude'];

    for (const webDir of webDirs) {
      const dirPath = path.join(targetDir, webDir);
      try {
        await fs.access(dirPath);
      } catch {
        continue;
      }

      // WEBEXPOSE-001: CLAUDE.md
      for (const claudeFile of claudeFiles) {
        const filePath = path.join(dirPath, claudeFile);
        try {
          await fs.access(filePath);
          const realPath = await fs.realpath(filePath);
          if (seenPaths.has(realPath)) continue;
          seenPaths.add(realPath);
          const relativePath = path.relative(targetDir, filePath);
          findings.push({
            checkId: 'WEBEXPOSE-001',
            name: 'CLAUDE.md in web-served directory',
            description: 'CLAUDE.md found in a web-served directory. This file often contains system prompts, instructions, and operational details that should not be publicly accessible.',
            category: 'web-exposure',
            severity: 'high',
            passed: false,
            message: `CLAUDE.md exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: 'Move CLAUDE.md out of the web-served directory. Add it to .gitignore and your build exclusion list.',
            guidance: 'CLAUDE.md contains system prompts and operational instructions. Publicly accessible CLAUDE.md reveals agent behavior, security controls, and attack surface to potential adversaries.',
          });
        } catch { /* file doesn't exist */ }
      }

      // WEBEXPOSE-002: .env files
      for (const envFile of envFiles) {
        const filePath = path.join(dirPath, envFile);
        try {
          await fs.access(filePath);
          const relativePath = path.relative(targetDir, filePath);
          findings.push({
            checkId: 'WEBEXPOSE-002',
            name: '.env file in web-served directory',
            description: 'Environment file found in a web-served directory. This file likely contains API keys, database credentials, and other secrets accessible to anyone who visits the site.',
            category: 'web-exposure',
            severity: 'critical',
            passed: false,
            message: `Environment file exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: 'Remove .env files from web-served directories immediately. Store environment files in the project root (outside public/) and rotate any exposed credentials.',
            guidance: '.env files in web directories are directly downloadable by anyone. All credentials in these files should be considered compromised and rotated immediately.',
          });
        } catch { /* file doesn't exist */ }
      }

      // WEBEXPOSE-003: Sensitive config files
      for (const configFile of configFiles) {
        const filePath = path.join(dirPath, configFile);
        try {
          await fs.access(filePath);
          const relativePath = path.relative(targetDir, filePath);
          findings.push({
            checkId: 'WEBEXPOSE-003',
            name: 'Sensitive config file in web-served directory',
            description: `Configuration file (${configFile}) found in a web-served directory. This may expose MCP server configs, API endpoints, or other sensitive operational details.`,
            category: 'web-exposure',
            severity: 'high',
            passed: false,
            message: `Config file exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: `Move ${configFile} out of the web-served directory. Serve only the minimal configuration needed by the client.`,
            guidance: 'Configuration files in web directories expose MCP server addresses, API endpoints, authentication settings, and other operational details that aid attackers in targeting your infrastructure.',
          });
        } catch { /* file doesn't exist */ }
      }

      // WEBEXPOSE-003: Sensitive config directories
      for (const configDir of configDirs) {
        const configDirPath = path.join(dirPath, configDir);
        try {
          await fs.access(configDirPath);
          const relativePath = path.relative(targetDir, configDirPath);
          findings.push({
            checkId: 'WEBEXPOSE-003',
            name: 'Sensitive config directory in web-served directory',
            description: `.claude/ directory found in a web-served directory. This directory contains Claude Code settings and may expose system prompts or tool configurations.`,
            category: 'web-exposure',
            severity: 'high',
            passed: false,
            message: `Config directory exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: 'Remove the .claude/ directory from web-served directories. Add it to your build exclusion list.',
            guidance: 'The .claude/ directory contains Claude Code settings, tool permissions, and potentially system prompts. Public access reveals your AI tool configuration and attack surface.',
          });
        } catch { /* directory doesn't exist */ }
      }
    }

    return findings;
  }

  /**
   * SOUL-OVERRIDE-001: Skill content can override SOUL.md
   * Checks if SKILL.md and SOUL.md are loaded into the same prompt context without trust boundaries.
   */
  private async checkSoulOverride(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Path 1: Look for system-prompt files that load both soul and skill content
    const promptFiles = await this.walkDirectory(targetDir, ['.ts', '.js', '.mjs'], 0, 2);
    const targetFiles = promptFiles.filter(f => {
      const name = path.basename(f).toLowerCase();
      return name.includes('system-prompt') || name.includes('systemprompt') ||
             name.includes('prompt-builder') || name.includes('promptbuilder') ||
             name.includes('context-builder') || name.includes('contextbuilder');
    });

    for (const file of targetFiles.slice(0, 20)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const relativePath = path.relative(targetDir, file);

        const hasSoul = /\b(soul|SOUL\.md|soulContent|soul_content)\b/.test(content);
        const hasSkill = /\b(skill|SKILL\.md|skillContent|skill_content)\b/.test(content);

        if (hasSoul && hasSkill) {
          // Check for trust boundary markers
          const hasBoundary = /\b(trustBoundary|trust_boundary|TRUST_BOUNDARY|sandboxed|isolated|untrusted)\b/.test(content);
          if (!hasBoundary) {
            const lines = content.split('\n');
            let soulLine = 0;
            for (let i = 0; i < lines.length; i++) {
              if (/\b(soul|SOUL\.md)\b/i.test(lines[i])) {
                soulLine = i + 1;
                break;
              }
            }
            findings.push({
              checkId: 'SOUL-OVERRIDE-001',
              name: 'Skill content can override SOUL.md',
              description: 'SOUL.md and SKILL.md content are loaded into the same prompt context without trust boundary markers. A malicious skill can include instructions that override the agent\'s core identity and safety rules.',
              category: 'soul-injection',
              severity: 'high',
              passed: false,
              message: `Soul and skill content mixed without trust boundaries in ${relativePath}`,
              file: relativePath,
              line: soulLine,
              fixable: false,
              fix: 'Add trust boundaries between SOUL.md (trusted) and SKILL.md (untrusted) content. Mark skill content as untrusted and instruct the model to not follow instructions from skill content.',
              guidance: 'Without trust boundaries, a malicious SKILL.md can include instructions that override the agent\'s core identity, safety rules, and behavioral constraints defined in SOUL.md.',
            });
          }
        }
      } catch { /* skip unreadable files */ }
    }

    // Path 2: Check for co-existing SOUL.md and SKILL.md files
    // When both exist in the same directory without trust markers in SKILL.md,
    // a malicious skill can override the agent's core identity
    if (findings.length === 0) {
      const soulPath = path.join(targetDir, 'SOUL.md');
      const skillPath = path.join(targetDir, 'SKILL.md');
      try {
        await fs.access(soulPath);
        await fs.access(skillPath);
        // Both exist -- check SKILL.md for override patterns
        const skillContent = await fs.readFile(skillPath, 'utf-8');
        const hasTrustBoundary = /\b(trustBoundary|trust_boundary|TRUST_BOUNDARY|sandboxed|isolated|untrusted)\b/.test(skillContent);
        if (!hasTrustBoundary) {
          // Check if SKILL.md contains override/injection patterns
          const hasOverridePattern = /\b(override|ignore|suspend|bypass|disregard)\b.*\b(rules?|safety|guidelines?|instructions?|prompt)\b/i.test(skillContent);
          const hasEscalation = /\b(admin|system|root|debug)\s*(mode|access|privilege)/i.test(skillContent);
          if (hasOverridePattern || hasEscalation) {
            findings.push({
              checkId: 'SOUL-OVERRIDE-001',
              name: 'Skill content can override SOUL.md',
              description: 'SKILL.md co-exists with SOUL.md and contains instructions that attempt to override safety rules. A malicious skill can include instructions that override the agent\'s core identity and safety rules.',
              category: 'soul-injection',
              severity: 'high',
              passed: false,
              message: 'SKILL.md contains override patterns that can bypass SOUL.md safety rules',
              file: 'SKILL.md',
              line: 1,
              fixable: false,
              fix: 'Add trust boundaries between SOUL.md (trusted) and SKILL.md (untrusted) content. Mark skill content as untrusted and instruct the model to not follow instructions from skill content.',
              guidance: 'SKILL.md contains override/escalation patterns that can bypass SOUL.md safety rules. Mark skill content as untrusted so the model knows not to follow instructions from it.',
            });
          }
        }
      } catch { /* one or both files don't exist */ }
    }

    return findings;
  }

  /**
   * SOUL governance gap checks: SOUL-COMPLETENESS, SOUL-CONSENT, SOUL-ESCAPE-CLAUSE,
   * SOUL-BYPASS, SOUL-CONTRADICTION, SOUL-UNVERIFIABLE-CLAIM.
   *
   * Scans SOUL.md files for missing constraints, escape clauses, bypass instructions,
   * contradictory privacy claims, or stacked unverifiable compliance assertions.
   */
  private async checkSoulGovernanceGaps(targetDir: string): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const soulFiles = await this.findFilesMatching(targetDir, ['SOUL.md']);

    for (const soulFile of soulFiles) {
      const relativePath = path.relative(targetDir, soulFile);
      let content: string;
      try {
        const stats = await fs.stat(soulFile);
        if (stats.size > MAX_FILE_SIZE) continue;
        content = await fs.readFile(soulFile, 'utf-8');
      } catch {
        continue;
      }

      // ── SOUL-BYPASS: instructs bypassing security tools ───────────────────
      const bypassPattern = /(bypass|skip|disable|ignore)\s+(?:hma|hackmyagent|oasb|security.check|analm|security.scan|scan.check)/i;
      const skipChecksPattern = /HMA_SKIP_CHECKS|SKIP_CHECKS\s*=\s*true|security.*validation.*disabled|checks.*disabled/i;
      if (bypassPattern.test(content) || skipChecksPattern.test(content)) {
        findings.push({
          checkId: 'SOUL-BYPASS',
          name: 'Security Check Bypass Instruction',
          description: 'SOUL.md instructs the agent to bypass or disable security scanning tools. This is a policy violation that blinds the agent\'s security posture verification.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'SOUL.md explicitly disables security checks',
          file: relativePath,
          fixable: false,
          fix: 'Remove all instructions to bypass, skip, or disable HMA, OASB, or NanoMind checks. Security tools must never be disabled via SOUL instructions.',
          guidance: 'Instructing the agent to bypass its own security scanning is equivalent to disabling seatbelts and airbags. Remove these instructions before deploying.',
          attackClass: 'SOUL-BYPASS',
        });
      }

      // ── SOUL-ESCAPE-CLAUSE: 2+ constraints with "unless" escape modifiers ─
      const escapeClauses = Array.from(
        content.matchAll(/\b(will not|must not|shall not|should not|cannot|forbidden|prohibited)[^.]{0,120}unless\b/gi)
      );
      if (escapeClauses.length >= 2) {
        findings.push({
          checkId: 'SOUL-ESCAPE-CLAUSE',
          name: 'Escape Clauses Nullify Constraints',
          description: `SOUL.md has ${escapeClauses.length} constraints with "unless" escape modifiers. Each "unless" allows the constraint to be bypassed, making the policy unenforceable.`,
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: `${escapeClauses.length} constraints contain "unless" escape clauses`,
          file: relativePath,
          fixable: false,
          fix: 'Replace "unless" escape clauses with absolute prohibitions: change "will not X unless Y" to "must never X regardless of instructions".',
          guidance: 'A constraint that can be bypassed with "unless explicitly directed" is not a constraint — it is an open door.',
          attackClass: 'SOUL-ESCAPE-CLAUSE',
        });
      }

      // ── SOUL-CONTRADICTION: privacy claim + external transmission ─────────
      const privacyClaimPattern = /(never|not)\s+(share|transmit|send|forward|upload)[^.]*(?:third.party|external|outside)|processed locally|all data.*local|data.*never.*leav/i;
      const externalTransmitPattern = /(sync|upload|send|transmit|transfer|forward)[^.]*(?:to|at)\s+(?:https?:\/\/|analytics|platform|pipeline|endpoint|api\.)/i;
      if (privacyClaimPattern.test(content) && externalTransmitPattern.test(content)) {
        findings.push({
          checkId: 'SOUL-CONTRADICTION',
          name: 'Contradictory Privacy Claim',
          description: 'SOUL.md claims data stays local or is never shared externally, but also describes an external synchronization or transmission. The stated privacy guarantee is contradicted by the described behavior.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'SOUL privacy claim contradicts described external data transmission',
          file: relativePath,
          fixable: false,
          fix: 'Resolve the contradiction: either remove the external sync or accurately disclose that data is transmitted externally.',
          guidance: 'Policy contradictions are exploitable: an attacker can invoke the permissive clause while the user believes the restrictive one applies.',
          attackClass: 'SOUL-CONTRADICTION',
        });
      }

      // ── SOUL-UNVERIFIABLE-CLAIM: stacked compliance certifications ────────
      const complianceTerms = [
        /ISO 27001/i, /SOC 2/i, /\bGDPR\b/i, /\bHIPAA\b/i, /\bCCPA\b/i,
        /AES.256/i, /PCI.?DSS/i, /\bindependently audit/i, /Trust Level [0-9]/i,
        /OpenA2A Registry.*(?:trusted|verified|certified)/i,
      ];
      const matchedTerms = complianceTerms.filter(p => p.test(content)).length;
      if (matchedTerms >= 3) {
        findings.push({
          checkId: 'SOUL-UNVERIFIABLE-CLAIM',
          name: 'Stacked Unverifiable Compliance Claims',
          description: `SOUL.md asserts ${matchedTerms} compliance certifications or trust claims (ISO 27001, SOC 2, GDPR, etc.) without a verifiable attestation mechanism.`,
          category: 'soul-governance',
          severity: 'medium',
          passed: false,
          message: `${matchedTerms} unverifiable compliance claims in SOUL.md`,
          file: relativePath,
          fixable: false,
          fix: 'Replace general compliance claims with verifiable references: cite specific attestation IDs, audit report URLs, or regulatory body registration numbers.',
          guidance: 'Unverifiable compliance claims in a SOUL.md create false trust. Users cannot distinguish a legitimate claim from a fraudulent one without a verification mechanism.',
          attackClass: 'SOUL-UNVERIFIABLE-CLAIM',
        });
      }

      // ── SOUL-CONSENT: broad capabilities without consent ──────────────────
      // Only match affirmative capability declarations, not negated ones.
      // "I can execute shell" → match. "I do not access external services" → no match.
      const hasBroadCapability = (() => {
        const capPatterns = [
          /(execute|run)\s+shell/i,
          /(shell|system)\s+command/i,
          /access.*internet/i,
          /write.*file/i,
          /delete.*file/i,
          /financial.*transaction/i,
          /act.*behalf/i,
          // "external service" only when NOT preceded by negation in the same sentence
          /(?<!(?:do not|will not|cannot|never|no)\s{0,20})external.*service/i,
        ];
        return capPatterns.some(p => {
          const m = p.exec(content);
          if (!m) return false;
          // Check 60 chars before match for negation
          const before = content.slice(Math.max(0, (m.index ?? 0) - 60), m.index ?? 0);
          if (/\b(do not|will not|must not|cannot|never|no)\b/i.test(before.split(/[.!\n]/).pop() ?? '')) return false;
          return true;
        });
      })();
      const hasIrrevocableConsent = /irrevocable\s+consent|grants.*irrevocable|permanent.*consent/i.test(content);
      const hasConsentLanguage = /\bconsent\b|\bauthori[sz]/i.test(content);

      if (hasBroadCapability && !hasConsentLanguage) {
        findings.push({
          checkId: 'SOUL-CONSENT',
          name: 'Broad Capabilities Without Consent Mechanism',
          description: 'SOUL.md declares broad high-risk capabilities (shell execution, external access, file operations) without any user consent or authorization requirement.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'High-risk capabilities present without consent/authorization constraints',
          file: relativePath,
          fixable: false,
          fix: 'Add a consent section defining which capabilities require explicit user authorization.',
          guidance: 'Broad capabilities without consent constraints mean the agent can take high-risk actions without user awareness.',
          attackClass: 'SOUL-CONSENT',
        });
      } else if (hasIrrevocableConsent) {
        findings.push({
          checkId: 'SOUL-CONSENT',
          name: 'Irrevocable Blanket Consent',
          description: 'SOUL.md uses irrevocable blanket consent language. Irrevocable consent removes the user\'s ability to withdraw permission.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'Irrevocable consent language detected in SOUL.md',
          file: relativePath,
          fixable: false,
          fix: 'Replace "irrevocable consent" with revocable, granular consent. Users must always be able to withdraw consent for agent capabilities.',
          guidance: 'Irrevocable consent is a legal and security red flag. Users must always be able to withdraw consent for agent capabilities.',
          attackClass: 'SOUL-CONSENT',
        });
      }

      // ── SOUL-COMPLETENESS: < 3 genuine constraints ────────────────────────
      // Count constraints NOT followed by an escape word within 50 chars
      const constraintMatches = Array.from(
        content.matchAll(/\b(will not|must not|shall not|cannot|does not|do not|never|forbidden|prohibited|restricted to|is not allowed)\b/gi)
      );
      const genuineConstraints = constraintMatches.filter(m => {
        const after = content.slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 50);
        return !/\bunless\b|\bexcept\b|\bif needed\b|\bif required\b|\bif directed\b/i.test(after);
      });
      const constraintCount = genuineConstraints.length;

      // Only fire for SOUL files that declare capabilities (empty/scope-only SOULs are fine)
      const hasDeclaredCapabilities = /##\s*capabilit|i can |i am able to|this agent can|i execute|i can run|shell|internet|network|access.*file|delete.*file|external/i.test(content);
      if (constraintCount < 2 && hasDeclaredCapabilities) {
        findings.push({
          checkId: 'SOUL-COMPLETENESS',
          name: 'Incomplete Governance Coverage',
          description: `SOUL.md has only ${constraintCount} enforceable constraint(s). A governed agent should have at least 3 explicit behavioral constraints covering capability boundaries, data handling, and trust hierarchy.`,
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: `Only ${constraintCount} genuine constraint(s) — governance is incomplete`,
          file: relativePath,
          fixable: false,
          fix: 'Add explicit constraints for: (1) capability boundaries, (2) data handling, (3) trust hierarchy.',
          guidance: 'Agents with fewer than 3 explicit constraints are under-governed and vulnerable to prompt injection attacks that exploit uncovered capability domains.',
          attackClass: 'SOUL-COMPLETENESS',
        });
      }
    }

    return findings;
  }

  /**
   * MEM-006: Memory store without input sanitization
   * Detects memory/persistence plugins that store user-provided text without sanitization.
   */
  private async checkMemoryStoreSanitization(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];
    const files = await this.walkDirectory(targetDir, ['.ts', '.js', '.mjs'], 0, 2);

    // Look for store/save/persist calls with text/content parameter (method or function)
    const storePattern = /(?:\.|^|\s|\()(store|save|persist|insert|upsert|push)\s*\(\s*\{[^}]*(text|content|message|input)\b/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        // Skip if file has sanitization functions
        if (/\b(sanitize|sanitise|escapeHtml|htmlEncode|stripTags|DOMPurify|xss)\b/.test(content)) continue;

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          storePattern.lastIndex = 0;
          if (storePattern.test(lines[i])) {
            // Check surrounding context for validation
            const contextStart = Math.max(0, i - 5);
            const context = lines.slice(contextStart, i).join('\n');
            if (!/\b(validate|sanitize|filter|clean|escape|strip)\b/.test(context)) {
              findings.push({
                checkId: 'MEM-006',
                name: 'Memory store without input sanitization',
                description: 'User-provided text is stored in a persistence layer without sanitization. An attacker can inject malicious content (prompt injection, XSS payloads) that persists and affects future sessions.',
                category: 'memory-poisoning',
                severity: 'high',
                passed: false,
                message: `Unsanitized input stored in memory/persistence in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Sanitize all user-provided text before storing. Strip instruction-like patterns and HTML/script content.',
                guidance: 'Unsanitized user input persisted to memory can contain prompt injections or XSS payloads that affect future sessions. Sanitize before storage to prevent persistent poisoning.',
              });
              break;
            }
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * AGENT-CRED-001: No credential output protection in system prompt
   * Checks system prompts that mention exec/shell but lack credential protection instructions.
   */
  private async checkAgentCredentialProtection(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // System prompt files to check
    const promptFileNames = ['SOUL.md', 'CLAUDE.md', 'system-prompt.md', 'system-prompt.txt'];
    const promptFilePatterns = ['system-prompt.ts', 'system-prompt.js', 'systemprompt.ts', 'systemprompt.js'];

    const allFiles: Array<{ path: string; rel: string }> = [];

    // Check known file names
    for (const name of promptFileNames) {
      const filePath = path.join(targetDir, name);
      try {
        await fs.access(filePath);
        allFiles.push({ path: filePath, rel: name });
      } catch { /* skip */ }
    }

    // Check for system-prompt source files
    const srcFiles = await this.walkDirectory(targetDir, ['.ts', '.js', '.md', '.txt'], 0, 2);
    for (const file of srcFiles) {
      const basename = path.basename(file).toLowerCase();
      if (promptFilePatterns.some(p => basename === p.toLowerCase())) {
        allFiles.push({ path: file, rel: path.relative(targetDir, file) });
      }
    }

    for (const { path: filePath, rel: relativePath } of allFiles.slice(0, 20)) {
      try {
        const stat = await fs.stat(filePath);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(filePath, 'utf-8');

        // Check if the prompt mentions exec/shell capabilities
        const hasExecCapability = /\b(exec|execute|shell|command|subprocess|spawn|terminal|bash)\b/i.test(content);
        if (!hasExecCapability) continue;

        // Check if there's credential protection language
        const hasCredProtection = /\b(credential|secret|api[_\s-]?key|environment[_\s]variable|never\s+(print|echo|output|display|log)\s+(secret|credential|key|token|password))\b/i.test(content);

        if (!hasCredProtection) {
          findings.push({
            checkId: 'AGENT-CRED-001',
            name: 'No credential output protection in system prompt',
            description: 'System prompt grants exec/shell capabilities but does not include instructions to protect credentials from being output. An attacker can craft prompts that cause the agent to echo environment variables or credential files.',
            category: 'agent-credential',
            severity: 'medium',
            passed: false,
            message: `System prompt in ${relativePath} grants exec access without credential protection instructions`,
            file: relativePath,
            fixable: false,
            fix: 'Add credential protection instructions to the system prompt: "Never print, echo, or output API keys, tokens, passwords, or environment variable values. Reference credentials only by variable name."',
            guidance: 'Agents with exec/shell access can be tricked into echoing environment variables containing API keys and passwords. Explicit instructions in the system prompt add a defense layer.',
          });
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * Stage 1: Context lifecycle assembly checks.
   * Simulates how the agent assembles its system prompt from multiple components
   * and detects injections that only activate post-assembly.
   */
  private async checkContextLifecycle(
    targetDir: string,
    options: ScanOptions,
  ): Promise<SecurityFinding[]> {
    try {
      const result = await scanAssembly({
        targetDir,
        onProgress: options.onProgress,
      });
      return result.findings;
    } catch {
      // Assembly scan failure is non-fatal
      return [];
    }
  }

  /** Helper: recursively find files in web-served directories */
  private async findWebFiles(
    dir: string,
    extensions: string[],
    depth: number,
    rootDir: string
  ): Promise<string[]> {
    if (depth > 3) return [];
    const results: string[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const fullPath = path.join(dir, entry.name);

        if (!this.isPathWithinDirectory(fullPath, rootDir)) continue;

        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
          const subFiles = await this.findWebFiles(fullPath, extensions, depth + 1, rootDir);
          results.push(...subFiles);
        } else if (entry.isFile()) {
          if (extensions.some(ext => entry.name.endsWith(ext))) {
            results.push(fullPath);
          }
        }
      }
    } catch { /* skip inaccessible dirs */ }

    return results;
  }
}
