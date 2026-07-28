/**
 * hackmyagent detect — Shadow AI Agent Audit
 *
 * Discovers AI agents running on this machine, MCP servers configured
 * across all platforms, local LLM processes, and AI config files in the
 * current project. Reports governance posture and risk classification.
 *
 * Design mirrors opena2a detect but is self-contained within HMA and uses
 * HMA's own SoulScanner for governance scoring.
 */

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { SoulScanner } from '../soul';
import type { SoulScanResult } from '../soul';
import { clampScoreToVerdictBand, clampDisclosure, isFailDirection } from '../ui/verdict-band';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DetectOptions {
  targetDir: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  exportCsv?: string;
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface DetectedAgent {
  name: string;
  pid: number;
  category: 'ai-assistant' | 'local-llm' | 'ai-plugin';
  identityStatus: 'identified' | 'no identity';
  governanceStatus: 'governed' | 'no governance';
  risk: RiskLevel;
}

export interface DetectedMcpServer {
  name: string;
  transport: 'stdio' | 'sse' | 'unknown';
  source: string;
  verified: boolean;
  capabilities: string[];
  risk: RiskLevel;
}

export interface AiConfigFile {
  file: string;
  tool: string;
  risk: RiskLevel;
  details: string;
}

export interface IdentitySummary {
  soulFiles: number;
  capabilityPolicies: number;
  totalAgents: number;
}

export interface Finding {
  severity: RiskLevel;
  category: string;
  title: string;
  detail: string;
  whyItMatters: string;
  remediation: string;
}

export interface DetectResult {
  scanTimestamp: string;
  scanDirectory: string;
  summary: {
    totalAgents: number;
    ungoverned: number;
    mcpServers: number;
    localLlms: number;
    aiConfigs: number;
    /**
     * Governance conformance for `scanDirectory`, after the #259
     * verdict-band clamp. Identical to what `scan-soul` reports for the same
     * directory whenever no fail-direction finding forced a clamp (#291).
     */
    governanceScore: number;
    /** Pre-clamp conformance — always exactly `scan-soul`'s score (#291). */
    governanceRaw: number;
    /** True when a fail-direction finding lowered `governanceScore`. */
    governanceClamped: boolean;
    recoverablePoints: number;
  };
  agents: DetectedAgent[];
  mcpServers: DetectedMcpServer[];
  aiConfigs: AiConfigFile[];
  identity: IdentitySummary;
  findings: Finding[];
}

// ---------------------------------------------------------------------------
// ANSI color helpers (respects NO_COLOR / --no-color)
// ---------------------------------------------------------------------------

function noColorEnabled(): boolean {
  return (
    process.env.NO_COLOR !== undefined ||
    process.env.TERM === 'dumb' ||
    process.argv.includes('--no-color') ||
    // Auto-strip on a non-TTY stdout, matching cli.ts's noColorEnv. `detect`
    // was the only command that respected NO_COLOR / --no-color but not the
    // pipe: `hackmyagent detect > out.txt` wrote 24 raw escape sequences into
    // the file while secure / scan-soul / check all came out clean (#253).
    !process.stdout.isTTY
  );
}

const nc = noColorEnabled();
const c = {
  bold:       nc ? '' : '\x1b[1m',
  dim:        nc ? '' : '\x1b[2m',
  reset:      nc ? '' : '\x1b[0m',
  green:      nc ? '' : '\x1b[32m',
  yellow:     nc ? '' : '\x1b[33m',
  red:        nc ? '' : '\x1b[31m',
  brightRed:  nc ? '' : '\x1b[91m',
  cyan:       nc ? '' : '\x1b[36m',
  white:      nc ? '' : '\x1b[97m',
};

const R = c.reset;
function bold(s: string): string  { return `${c.bold}${s}${R}`; }
function dim(s: string): string   { return `${c.dim}${s}${R}`; }
function green(s: string): string { return `${c.green}${s}${R}`; }
function yellow(s: string): string{ return `${c.yellow}${s}${R}`; }
function red(s: string): string   { return `${c.red}${s}${R}`; }
function brightRed(s: string): string { return `${c.brightRed}${s}${R}`; }
function cyan(s: string): string  { return `${c.cyan}${s}${R}`; }

function riskColor(level: RiskLevel): (s: string) => string {
  switch (level) {
    case 'critical': return brightRed;
    case 'high':     return red;
    case 'medium':   return yellow;
    case 'low':      return green;
  }
}

function riskLabel(level: RiskLevel): string {
  return riskColor(level)(level.toUpperCase());
}

// ── Unified UI helpers (match secure/check visual pattern) ───────────────

const METER_WIDTH = 20;

/** Progress-bar score string matching `displayUnifiedCheck` in cli.ts. */
function scoreMeter(value: number, max: number = 100): string {
  const pct = Math.max(0, Math.min(METER_WIDTH, Math.round((value / max) * METER_WIDTH)));
  const meterColor = value >= 70 ? c.green : value >= 40 ? c.yellow : c.red;
  const filled = '━'.repeat(pct);
  const empty = '━'.repeat(METER_WIDTH - pct);
  return `${meterColor}${filled}${R}${c.dim}${empty}${R} ${meterColor}${c.bold}${value}${R}${c.dim}/${max}${R}`;
}

/** Bolded severity label colored by risk level. */
function sevBadge(level: RiskLevel): string {
  const color = level === 'critical' ? c.brightRed : level === 'high' ? c.red : level === 'medium' ? c.yellow : c.green;
  return `${color}${c.bold}${level.toUpperCase()}${R}`;
}

/** `── Label ────` section divider matching cli.ts. */
function sectionHeader(label: string): string {
  const fill = Math.max(1, 56 - label.length);
  return `  ${c.dim}──${R} ${c.bold}${label}${R} ${c.dim}${'─'.repeat(fill)}${R}`;
}

// ---------------------------------------------------------------------------
// Agent patterns
// ---------------------------------------------------------------------------

const AGENT_PATTERNS: { name: string; category: DetectedAgent['category']; patterns: RegExp[] }[] = [
  { name: 'Claude Code',      category: 'ai-assistant', patterns: [/@anthropic-ai\/claude-code/i, /\bclaude\s*$/im, /\bclaude\s+/i] },
  { name: 'Cursor',           category: 'ai-assistant', patterns: [/Cursor\.app/i, /cursor-agent/i] },
  { name: 'GitHub Copilot',   category: 'ai-assistant', patterns: [/\bcopilot\b/i] },
  { name: 'Windsurf',         category: 'ai-assistant', patterns: [/Windsurf\.app/i, /windsurf-agent/i] },
  { name: 'Aider',            category: 'ai-assistant', patterns: [/\baider\b/] },
  { name: 'Continue',         category: 'ai-assistant', patterns: [/continue-server/i, /\bcontinue\.dev\b/i] },
  { name: 'Cline',            category: 'ai-assistant', patterns: [/\bcline\b/] },
  { name: 'Amazon Q',         category: 'ai-assistant', patterns: [/\bamazon-q\b/i, /\bq-developer\b/i] },
  { name: 'Tabnine',          category: 'ai-assistant', patterns: [/\btabnine\b/i] },
  { name: 'Sourcegraph Cody', category: 'ai-assistant', patterns: [/\bcody\b/i, /sourcegraph.*cody/i] },
  { name: 'Supermaven',       category: 'ai-assistant', patterns: [/\bsupermaven\b/i] },
  { name: 'Augment Code',     category: 'ai-assistant', patterns: [/\baugment\b/i] },
  // Local LLM runtimes
  { name: 'Ollama',      category: 'local-llm', patterns: [/\bollama\b/] },
  { name: 'LM Studio',   category: 'local-llm', patterns: [/lmstudio/i, /LM Studio/] },
  { name: 'LocalAI',     category: 'local-llm', patterns: [/\blocalai\b/i] },
  { name: 'llama.cpp',   category: 'local-llm', patterns: [/llama-server/i, /llama\.cpp/i, /\bllama-cli\b/i] },
  { name: 'vLLM',        category: 'local-llm', patterns: [/\bvllm\b/i] },
  { name: 'Open WebUI',  category: 'local-llm', patterns: [/open-webui/i] },
  { name: 'GPT4All',     category: 'local-llm', patterns: [/\bgpt4all\b/i] },
  { name: 'Jan',         category: 'local-llm', patterns: [/\bjan\.app\b/i, /Jan\.app/] },
];

// ---------------------------------------------------------------------------
// MCP config locations (home-relative)
// ---------------------------------------------------------------------------

const MCP_CONFIG_LOCATIONS = [
  { path: '.claude/mcp_servers.json',                                       label: 'Claude Code (global)' },
  { path: '.cursor/mcp.json',                                                label: 'Cursor (global)' },
  { path: '.config/windsurf/mcp.json',                                       label: 'Windsurf (global)' },
  { path: '.vscode/globalStorage/saoudrizwan.claude-dev/mcp_servers.json',   label: 'Cline (global)' },
];

const PROJECT_MCP_FILES = ['mcp.json', '.mcp.json', '.mcp/config.json'];

const HIGH_RISK_CAPABILITIES   = ['execute', 'shell', 'bash', 'terminal', 'run', 'eval'];
const MEDIUM_RISK_CAPABILITIES = ['filesystem', 'file', 'write', 'database', 'db', 'sql', 'network', 'http', 'fetch'];
void HIGH_RISK_CAPABILITIES;
void MEDIUM_RISK_CAPABILITIES;

// ---------------------------------------------------------------------------
// AI config patterns
// ---------------------------------------------------------------------------

const AI_CONFIG_PATTERNS: { files: string[]; tool: string }[] = [
  { files: ['.cursorrules', '.cursor/config.json', '.cursor/rules'],              tool: 'Cursor' },
  { files: ['.claude/settings.json', '.claude/settings.local.json', 'CLAUDE.md'], tool: 'Claude Code' },
  { files: ['.github/copilot-instructions.md', '.copilot'],                       tool: 'GitHub Copilot' },
  { files: ['.windsurfrules', '.windsurf/config.json'],                            tool: 'Windsurf' },
  { files: ['.aider.conf.yml', '.aiderignore'],                                    tool: 'Aider' },
  { files: ['.continue/config.json', '.continuerules'],                            tool: 'Continue' },
  { files: ['langchain.config.js', 'langchain.config.ts'],                         tool: 'LangChain' },
  { files: ['.env.ai', 'ai.config.json', 'ai.config.yml'],                        tool: 'AI Framework' },
];

// ---------------------------------------------------------------------------
// MCP capability inference
// ---------------------------------------------------------------------------

const CAPABILITY_DESCRIPTIONS: Record<string, string> = {
  'filesystem':     'Can read and write files on your machine',
  'shell-access':   'Can run any command on your computer',
  'database':       'Can read and modify your database',
  'network':        'Can make requests to external services',
  'browser':        'Can control a web browser and visit pages',
  'source-control': 'Can read and push code to your repositories',
  'messaging':      'Can send messages on your behalf',
  'payments':       'Can access payment and billing systems',
  'cloud-services': 'Can access your cloud infrastructure',
  'unknown':        'Capabilities not determined',
};

function capabilityDescription(cap: string): string {
  return CAPABILITY_DESCRIPTIONS[cap] ?? cap;
}

function inferMcpCapabilities(name: string, config: Record<string, unknown>): string[] {
  const caps: string[] = [];
  const nameLower = name.toLowerCase();
  const args = Array.isArray(config.args) ? config.args.map(String) : [];
  const command = typeof config.command === 'string' ? config.command : '';
  const combined = `${nameLower} ${command} ${args.join(' ')}`.toLowerCase();

  if (/filesys|file|fs\b/.test(combined))                  caps.push('filesystem');
  if (/shell|bash|terminal|exec/.test(combined))            caps.push('shell-access');
  if (/database|db|sql|postgres|mysql|sqlite/.test(combined)) caps.push('database');
  if (/network|http|fetch|curl|api/.test(combined))         caps.push('network');
  if (/browser|playwright|puppeteer|selenium/.test(combined)) caps.push('browser');
  if (/git\b|github|gitlab/.test(combined))                 caps.push('source-control');
  if (/slack|email|discord|teams/.test(combined))           caps.push('messaging');
  if (/stripe|payment|billing/.test(combined))              caps.push('payments');
  if (/supabase|firebase|cloud/.test(combined))             caps.push('cloud-services');

  if (caps.length === 0) caps.push('unknown');
  return caps;
}

function classifyMcpRisk(capabilities: string[], transport: string): RiskLevel {
  if (capabilities.includes('shell-access')) return 'critical';
  if (transport === 'sse' && (capabilities.includes('database') || capabilities.includes('payments'))) {
    return 'critical';
  }
  if (capabilities.includes('database') || capabilities.includes('payments')) return 'high';
  if (capabilities.includes('network') || capabilities.includes('filesystem')) return 'medium';
  return 'medium';
}

// ---------------------------------------------------------------------------
// Process scanning
// ---------------------------------------------------------------------------

export function scanProcesses(psOutput?: string): DetectedAgent[] {
  let output: string;
  if (psOutput !== undefined) {
    output = psOutput;
  } else {
    try {
      output = execSync('ps aux', { encoding: 'utf-8', timeout: 5000 });
    } catch {
      return [];
    }
  }

  const lines = output.split('\n');
  const agents: DetectedAgent[] = [];
  const seen = new Set<string>();

  for (const line of lines) {
    for (const agent of AGENT_PATTERNS) {
      if (seen.has(agent.name)) continue;
      if (!agent.patterns.some((p) => p.test(line))) continue;

      const parts = line.trim().split(/\s+/);
      const pid = parseInt(parts[1], 10);
      if (isNaN(pid)) continue;

      agents.push({
        name: agent.name,
        pid,
        category: agent.category,
        identityStatus: 'no identity',
        governanceStatus: 'no governance',
        risk: agent.category === 'local-llm' ? 'medium' : 'high',
      });
      seen.add(agent.name);
    }
  }

  return agents;
}

// ---------------------------------------------------------------------------
// MCP config parsing
// ---------------------------------------------------------------------------

export function parseMcpConfig(filePath: string, label: string): DetectedMcpServer[] {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const config = JSON.parse(content);
    const servers: DetectedMcpServer[] = [];

    const serversObj = config.mcpServers ?? config.servers ?? config;
    if (typeof serversObj !== 'object' || serversObj === null || Array.isArray(serversObj)) return [];

    for (const [name, entry] of Object.entries(serversObj)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const e = entry as Record<string, unknown>;

      let transport: 'stdio' | 'sse' | 'unknown' = 'unknown';
      if (e.command || e.args) transport = 'stdio';
      if (e.url || e.transport === 'sse') transport = 'sse';
      if (e.transport === 'stdio') transport = 'stdio';

      const capabilities = inferMcpCapabilities(name, e);
      const risk = classifyMcpRisk(capabilities, transport);

      servers.push({ name, transport, source: label, verified: false, capabilities, risk });
    }

    return servers;
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// MCP server scanning
// ---------------------------------------------------------------------------

export function scanMcpServers(targetDir: string): DetectedMcpServer[] {
  const home = os.homedir();
  const servers: DetectedMcpServer[] = [];

  // Global tool configs (home-relative)
  for (const loc of MCP_CONFIG_LOCATIONS) {
    servers.push(...parseMcpConfig(path.join(home, loc.path), loc.label));
  }

  // Claude Code project-level .mcp.json
  servers.push(...parseMcpConfig(path.join(home, '.claude', '.mcp.json'), 'Claude Code (project)'));

  // VS Code extension MCP configs
  const vscodeExtDir = path.join(home, '.vscode', 'extensions');
  try {
    const entries = fs.readdirSync(vscodeExtDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      servers.push(
        ...parseMcpConfig(path.join(vscodeExtDir, entry.name, 'mcp.json'), `VS Code: ${entry.name}`)
      );
    }
  } catch { /* directory may not exist */ }

  // Project-local MCP files
  for (const filename of PROJECT_MCP_FILES) {
    servers.push(...parseMcpConfig(path.join(targetDir, filename), `${filename} (project)`));
  }

  return servers;
}

// ---------------------------------------------------------------------------
// AI config file discovery
// ---------------------------------------------------------------------------

export function scanAiConfigs(targetDir: string): AiConfigFile[] {
  const configs: AiConfigFile[] = [];

  for (const pattern of AI_CONFIG_PATTERNS) {
    for (const file of pattern.files) {
      const fullPath = path.join(targetDir, file);
      let stats: ReturnType<typeof fs.statSync> | undefined;
      try { stats = fs.statSync(fullPath); } catch { continue; }
      if (!stats) continue;
      if (stats.size > 1024 * 1024) continue; // skip files > 1MB

      let details = `${pattern.tool} configuration`;
      let risk: RiskLevel = 'low';

      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        const hasApiKey = /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}/i.test(content);
        const hasPermissions = /(?:allow|permit|grant|unrestricted|all\s+bash)/i.test(content);

        if (hasApiKey) {
          risk = 'critical';
          details = `${pattern.tool} config contains credential references`;
        } else if (hasPermissions) {
          risk = 'high';
          details = `${pattern.tool} config grants broad permissions`;
        }
      } catch { /* file unreadable */ }

      configs.push({ file, tool: pattern.tool, risk, details });
    }
  }

  return configs;
}

// ---------------------------------------------------------------------------
// Identity & governance scanning
// ---------------------------------------------------------------------------

export function scanIdentity(targetDir: string): IdentitySummary {
  let soulFiles = 0;
  let capabilityPolicies = 0;

  // SOUL.md in project root or .opena2a/
  for (const p of [
    path.join(targetDir, 'SOUL.md'),
    path.join(targetDir, '.opena2a', 'SOUL.md'),
  ]) {
    if (fs.existsSync(p)) soulFiles++;
  }

  // Capability policy files
  const policyPaths = [
    path.join(targetDir, '.opena2a', 'policy.yml'),
    path.join(targetDir, '.opena2a', 'policy.yaml'),
    path.join(targetDir, '.opena2a', 'policy.json'),
    path.join(targetDir, 'opena2a.policy.yml'),
    path.join(targetDir, 'opena2a.policy.yaml'),
  ];
  for (const p of policyPaths) {
    if (fs.existsSync(p)) capabilityPolicies++;
  }

  return { soulFiles, capabilityPolicies, totalAgents: 0 };
}

// ---------------------------------------------------------------------------
// Governance scoring
// ---------------------------------------------------------------------------

/**
 * Governance score for `detect` (#291).
 *
 * There is one Governance number in this tool and `scan-soul`'s control
 * conformance computes it. `detect` consumes that number; it does not have
 * a second opinion.
 *
 * The model this replaced scored *presence*, not substance. It started at
 * 100 and deducted, and the only thing it asked of governance was whether a
 * file existed — `detect()` marked every agent `governed` the moment a
 * SOUL.md was on disk. So the two surfaces answered the same question about
 * the same directory in opposite directions:
 *
 *   SOUL.md containing one line of prose   scan-soul   0/100   detect 100/100
 *   a real CLAUDE.md (22/100 conformance)  scan-soul  22/100   detect 100/100
 *   no governance file at all              scan-soul   0/100   detect  55/100
 *
 * Both numbers shipped under the label "Governance". That is a data-integrity
 * defect rather than a display one, so the models are reconciled instead of
 * one of them being renamed: conformance is authoritative because it measures
 * whether controls actually exist, and because it is already the figure the
 * Registry publishes (`publish.ts` -> `subReports.soul`). `detect` has no
 * publish path, so reconciling it moves no already-published number.
 *
 * The deductions the old model applied — ungoverned agents, project-local
 * critical MCP servers, credentials in AI configs — are NOT folded into the
 * number. They are host- and project-inventory facts, they remain findings
 * with their own severities, and they reach the meter the same way every
 * other fail-direction finding does: through the #259 verdict-band clamp,
 * which can only ever lower a score and always discloses the pre-clamp value.
 * Averaging a substance measure against a presence measure would have
 * produced a third number that means nothing.
 */
function reconciledGovernanceScore(
  soul: SoulScanResult,
  findings: readonly Finding[],
): { governanceScore: number; governanceRaw: number; governanceClamped: boolean; deductions: number } {
  const governanceRaw = soul.score;
  const { score, clamped } = clampScoreToVerdictBand(governanceRaw, findings);

  return {
    governanceScore: score,
    governanceRaw,
    governanceClamped: clamped,
    // Recoverable points are the conformance gap: the controls `harden-soul`
    // would add. Measured against the raw score, because clearing the
    // findings that caused a clamp is a separate path already spelled out in
    // the findings themselves.
    deductions: Math.max(0, 100 - governanceRaw),
  };
}

// ---------------------------------------------------------------------------
// Finding generation
// ---------------------------------------------------------------------------

function generateFindings(result: Omit<DetectResult, 'findings'>): Finding[] {
  const findings: Finding[] = [];

  // Ungoverned agents
  const ungoverned = result.agents.filter((a) => a.governanceStatus === 'no governance');
  if (ungoverned.length > 0) {
    const noSoul = result.identity.soulFiles === 0;
    const detail = ungoverned.map((a) => a.name).join(', ')
      + (noSoul ? ' — no SOUL.md governance file found' : '');
    findings.push({
      severity: 'high',
      category: 'governance',
      title: `${ungoverned.length} AI agent${ungoverned.length !== 1 ? 's' : ''} running without governance`,
      detail,
      whyItMatters:
        'These agents can take actions in your project but have no rules defining what they '
        + 'should or should not do. A SOUL.md file sets behavioral boundaries — what agents can and '
        + 'cannot do, and what requires human approval.',
      remediation: 'hackmyagent harden-soul .',
    });
  }

  // Project-local critical MCP servers
  const projectCriticalMcp = result.mcpServers.filter(
    (s) => s.risk === 'critical' && s.source.includes('(project)')
  );
  if (projectCriticalMcp.length > 0) {
    const details = projectCriticalMcp.map((s) => {
      const caps = s.capabilities.filter((cc) => cc !== 'unknown');
      return `${s.name}: ${caps.map((cc) => capabilityDescription(cc).toLowerCase()).join(', ')}`;
    });
    findings.push({
      severity: 'critical',
      category: 'mcp',
      title: `${projectCriticalMcp.length} project MCP server${projectCriticalMcp.length !== 1 ? 's' : ''} with sensitive access`,
      detail: details.join('; '),
      whyItMatters:
        'These MCP servers are configured in your project and grant access to sensitive operations '
        + 'like running shell commands or accessing databases. '
        + 'Running a security scan confirms they match what you intended to install.',
      remediation: 'hackmyagent secure .',
    });
  }

  // Unverified project-local MCP servers (non-critical, not already flagged)
  const projectUnverified = result.mcpServers.filter(
    (s) => !s.verified && s.source.includes('(project)') && s.risk !== 'critical'
  );
  if (projectUnverified.length > 0) {
    const names = projectUnverified.map((s) => s.name);
    const preview = names.slice(0, 5).join(', ');
    const detailTail = names.length > 5 ? `${preview}, +${names.length - 5} more` : preview;
    findings.push({
      severity: 'medium',
      category: 'mcp',
      title: `${projectUnverified.length} project MCP server${projectUnverified.length !== 1 ? 's' : ''} without a security scan`,
      detail: detailTail,
      whyItMatters:
        'These servers are configured in your project but have not been scanned for security issues. '
        + 'Running hackmyagent secure surfaces any vulnerabilities in their configuration.',
      remediation: 'hackmyagent secure .',
    });
  }

  // Credentials in AI config files
  const criticalConfigs = result.aiConfigs.filter((c) => c.risk === 'critical');
  if (criticalConfigs.length > 0) {
    findings.push({
      severity: 'critical',
      category: 'config',
      title: 'AI config files contain credential references',
      detail: criticalConfigs.map((cc) => cc.file).join(', '),
      whyItMatters:
        'API keys or tokens appear to be stored directly in these configuration files. '
        + 'Anyone with repository access can see and use these credentials.',
      remediation: 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
    });
  }

  // Broad permissions in AI configs
  const highConfigs = result.aiConfigs.filter((c) => c.risk === 'high');
  if (highConfigs.length > 0) {
    findings.push({
      severity: 'high',
      category: 'config',
      title: 'AI config files grant broad permissions',
      detail: highConfigs.map((cc) => cc.file).join(', '),
      whyItMatters:
        'These configs allow AI agents to perform a wide range of actions without restrictions. '
        + 'Broad permissions increase risk if an agent behaves unexpectedly.',
      remediation: 'hackmyagent scan-soul .',
    });
  }

  // No SOUL.md when agents present but no ungoverned finding yet
  if (result.identity.soulFiles === 0 && result.agents.length > 0 && ungoverned.length === 0) {
    findings.push({
      severity: 'medium',
      category: 'governance',
      title: 'No SOUL.md governance file in this project',
      detail: 'Agents are governed by capability policies but have no SOUL.md behavioral boundaries.',
      whyItMatters:
        'A SOUL.md file defines what an agent should and should not do beyond capability restrictions — '
        + 'handling errors, sensitive data, and when to ask for human approval.',
      remediation: 'hackmyagent harden-soul .',
    });
  }

  // Sort by severity
  const order: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return findings;
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function generateAssetCsv(result: DetectResult): string {
  const rows: string[] = [];
  const hostname = os.hostname();
  const username = os.userInfo().username;
  const scanTime = result.scanTimestamp;
  const scanDir = result.scanDirectory;

  rows.push('Hostname,Username,Scan Directory,Scan Timestamp,Asset Type,Name,Source,Transport,Capabilities,Risk');
  const deviceCols = [csvEscape(hostname), csvEscape(username), csvEscape(scanDir), scanTime].join(',');

  for (const agent of result.agents) {
    rows.push([deviceCols, 'AI Agent', csvEscape(agent.name), 'Running process', '', agent.category, agent.risk].join(','));
  }
  for (const server of result.mcpServers) {
    const caps = server.capabilities.filter((cap) => cap !== 'unknown');
    rows.push([
      deviceCols,
      'MCP Server',
      csvEscape(server.name),
      csvEscape(server.source),
      server.transport,
      csvEscape(caps.map(capabilityDescription).join('; ')),
      server.risk,
    ].join(','));
  }
  for (const config of result.aiConfigs) {
    rows.push([deviceCols, 'AI Config', csvEscape(config.file), csvEscape(config.tool), '', csvEscape(config.details), config.risk].join(','));
  }

  return rows.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Text formatting
// ---------------------------------------------------------------------------

function formatText(result: DetectResult, verbose: boolean, targetDir: string): string {
  const lines: string[] = [];
  const { summary } = result;
  const score = summary.governanceScore;
  // Best achievable governance: every applicable control covered, and no
  // fail-direction finding left to cap the result. Both routes are spelled
  // out in the Path forward line below.
  //
  // NOT `score + recoverablePoints`. Recoverable points measure the
  // conformance gap only, so a tree already at full conformance but capped
  // by a CRITICAL projected 69 -> 69 and the path forward vanished — the one
  // case where the operator most needs to be told that clearing the finding
  // restores the number.
  const projected = 100;

  // Severity counts
  const critical = result.findings.filter((f) => f.severity === 'critical').length;
  const high = result.findings.filter((f) => f.severity === 'high').length;
  const medium = result.findings.filter((f) => f.severity === 'medium').length;
  const low = result.findings.filter((f) => f.severity === 'low').length;
  const total = critical + high + medium + low;

  // ── Header ────────────────────────────────────────────────────────
  const dirBase = path.basename(targetDir) || targetDir;
  const metaParts = [
    'shadow ai audit',
    `${os.hostname()}`,
    summary.totalAgents > 0 ? `${summary.totalAgents} agent${summary.totalAgents === 1 ? '' : 's'}` : null,
    summary.mcpServers > 0 ? `${summary.mcpServers} mcp server${summary.mcpServers === 1 ? '' : 's'}` : null,
  ].filter(Boolean);

  lines.push('');
  lines.push(`  ${c.bold}${c.white}${dirBase}${R}  ${c.dim}${metaParts.join(' · ')}${R}`);

  // ── Verdict + Score ───────────────────────────────────────────────
  let verdictColor: string;
  let verdictText: string;
  if (critical > 0) {
    verdictColor = c.brightRed;
    verdictText = `${critical} critical issue${critical > 1 ? 's' : ''} found`;
  } else if (high > 0) {
    verdictColor = c.red;
    verdictText = `${high} high-severity issue${high > 1 ? 's' : ''} found`;
  } else if (total > 0) {
    verdictColor = c.yellow;
    verdictText = `${total} issue${total > 1 ? 's' : ''} found`;
  } else if (summary.totalAgents === 0 && summary.mcpServers === 0 && summary.aiConfigs === 0) {
    verdictColor = c.dim;
    verdictText = 'No AI agents, MCP servers, or AI configs detected';
  } else {
    verdictColor = c.green;
    verdictText = 'All detected AI tools have governance in place';
  }
  lines.push(`  ${verdictColor}${c.bold}${verdictText}${R}`);
  lines.push('');
  // #291/#259: when a fail-direction finding floored the number, name the
  // pre-clamp value. The clamp adds information; it must not look like the
  // conformance measurement itself came out lower than `scan-soul` says.
  const govClampNote = clampDisclosure({
    rawScore: summary.governanceRaw,
    score,
    clamped: summary.governanceClamped,
  });
  lines.push(`  Governance  ${scoreMeter(score)}${govClampNote}`);

  // ── Findings ──────────────────────────────────────────────────────
  if (result.findings.length > 0) {
    const summaryParts: string[] = [];
    if (critical > 0) summaryParts.push(`${c.brightRed}${c.bold}${critical} critical${R}`);
    if (high > 0) summaryParts.push(`${c.red}${c.bold}${high} high${R}`);
    if (medium > 0) summaryParts.push(`${c.yellow}${medium} medium${R}`);
    if (low > 0) summaryParts.push(`${c.dim}${low} low${R}`);

    lines.push('');
    lines.push(sectionHeader('Findings'));
    lines.push(`  ${summaryParts.join('  ')}`);

    const limit = verbose ? result.findings.length : 10;
    const shown = Math.min(limit, result.findings.length);
    for (let i = 0; i < shown; i++) {
      const f = result.findings[i];
      const pipe = riskColor(f.severity)('│');
      lines.push('');
      lines.push(`  ${pipe} ${sevBadge(f.severity)}  ${c.bold}${c.white}${f.title}${R}`);
      if (f.detail) lines.push(`  ${pipe} ${c.dim}${f.detail}${R}`);
      if (f.whyItMatters) lines.push(`  ${pipe} ${f.whyItMatters}`);
      if (f.remediation) lines.push(`  ${pipe} ${c.cyan}Fix:${R} ${cyan(f.remediation)}`);
    }
    const remaining = result.findings.length - shown;
    if (remaining > 0) {
      lines.push('');
      lines.push(`  ${c.dim}+ ${remaining} more (run with --verbose to see all)${R}`);
    }

  }

  // ── Path forward ──────────────────────────────────────────────────
  //
  // Named after what actually moves the number (#291). The meter is
  // governance conformance, so the recoverable points are missing controls
  // and `harden-soul` is what recovers them — not "fixing N high", which is
  // what this said while the score was finding-driven. Attributing 22 -> 100
  // to clearing a HIGH finding was a promise the tool could not keep.
  //
  // Rendered outside the findings block: a directory can sit at 22/100
  // conformance with nothing else wrong, and that must not be a dead end.
  if (projected > score) {
    const steps: string[] = [];
    if (summary.governanceRaw < 100) steps.push('adding the missing governance controls');
    // Gated on fail-direction, NOT on `governanceClamped`. The clamp only
    // fires once the raw score is above the band floor, but a critical or
    // high finding caps the achievable score at VERDICT_FAIL_CLAMP the whole
    // time. Gating on the clamp promised "19 -> 100 by adding the missing
    // governance controls" on a tree with an outstanding CRITICAL, where
    // full conformance would have landed on 69, not 100.
    if (isFailDirection(result.findings)) {
      const sevParts: string[] = [];
      if (critical > 0) sevParts.push(`${critical} critical`);
      if (high > 0) sevParts.push(`${high} high`);
      if (sevParts.length > 0) steps.push(`clearing ${sevParts.join(' + ')}`);
    }
    if (steps.length > 0) {
      lines.push('');
      lines.push(`  ${c.cyan}${c.bold}Path forward:${R} ${c.cyan}${score} ${c.dim}->${R} ${c.green}${c.bold}${projected}${R} ${c.cyan}by ${steps.join(' and ')}${R}`);
    }
  }

  // ── Running AI Agents ─────────────────────────────────────────────
  const assistants = result.agents.filter((a) => a.category === 'ai-assistant');
  const llms = result.agents.filter((a) => a.category === 'local-llm');
  if (assistants.length + llms.length > 0) {
    lines.push('');
    lines.push(sectionHeader(`Running AI Agents (${assistants.length + llms.length})`));
    for (const agent of [...assistants, ...llms]) {
      const nameCol = agent.name.padEnd(22);
      const isGoverned = agent.governanceStatus === 'governed';
      const govStr = isGoverned ? green('governed') : yellow('ungoverned');
      const pidStr = verbose ? dim(` (PID ${agent.pid})`) : '';
      const fixHint = !isGoverned ? `  ${dim('→')}  ${cyan('hackmyagent harden-soul .')}` : '';
      lines.push(`  ${nameCol}${govStr}${pidStr}${fixHint}`);
    }
  }

  // ── MCP Servers ───────────────────────────────────────────────────
  const projectMcp = result.mcpServers.filter((s) => s.source.includes('(project)'));
  const globalMcp = result.mcpServers.filter((s) => !s.source.includes('(project)'));

  if (result.mcpServers.length > 0) {
    lines.push('');
    lines.push(sectionHeader(`MCP Servers (${result.mcpServers.length})`));

    if (projectMcp.length > 0) {
      const riskOrder: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      projectMcp.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);

      lines.push(`  ${c.bold}Project-local${R} ${c.dim}(${projectMcp.length})${R}`);
      const mcpLimit = verbose ? projectMcp.length : 10;
      const mcpShown = Math.min(mcpLimit, projectMcp.length);
      const maxName = Math.min(28, Math.max(...projectMcp.slice(0, mcpShown).map((s) => s.name.length)));
      for (let i = 0; i < mcpShown; i++) {
        const server = projectMcp[i];
        const nameCol = server.name.padEnd(maxName + 2);
        const riskStr = riskColor(server.risk)(server.risk.toUpperCase());
        const realCaps = server.capabilities.filter((cap) => cap !== 'unknown');
        const capsStr = realCaps.length > 0
          ? dim(` — ${realCaps.map((cap) => capabilityDescription(cap).toLowerCase()).join(', ')}`)
          : '';
        lines.push(`    ${nameCol}${riskStr}${capsStr}`);
      }
      const mcpRemaining = projectMcp.length - mcpShown;
      if (mcpRemaining > 0) {
        lines.push(`    ${c.dim}+ ${mcpRemaining} more (run with --verbose to see all)${R}`);
      }
    }

    if (globalMcp.length > 0) {
      if (verbose) {
        lines.push(`  ${c.bold}Machine-wide${R} ${c.dim}(${globalMcp.length})${R}`);
        const maxName = Math.min(28, Math.max(...globalMcp.map((s) => s.name.length)));
        for (const server of globalMcp) {
          const nameCol = server.name.padEnd(maxName + 2);
          const realCaps = server.capabilities.filter((cap) => cap !== 'unknown');
          const capsStr = realCaps.length > 0
            ? dim(` — ${realCaps.map((cap) => capabilityDescription(cap).toLowerCase()).join(', ')}`)
            : '';
          lines.push(`    ${nameCol}${capsStr}`);
        }
      } else {
        const sensitiveCaps = globalMcp.filter((s) =>
          s.capabilities.some((cap) => ['shell-access', 'database', 'payments', 'cloud-services'].includes(cap))
        );
        let globalLine = `  ${c.dim}Machine-wide (${globalMcp.length})${R}`;
        if (sensitiveCaps.length > 0) {
          const names = sensitiveCaps.map((s) => s.name).join(', ');
          globalLine += dim(` — ${sensitiveCaps.length} with sensitive access: ${names}`);
        }
        lines.push(globalLine);
        lines.push(`    ${c.dim}(run with --verbose to see full list)${R}`);
      }
    }
  }

  // ── AI Config Files ───────────────────────────────────────────────
  const noteworthyConfigs = result.aiConfigs.filter((cc) => cc.risk !== 'low');
  if (result.aiConfigs.length > 0 && (noteworthyConfigs.length > 0 || verbose)) {
    lines.push('');
    lines.push(sectionHeader(`AI Config Files (${result.aiConfigs.length})`));
    const configsToShow = verbose ? result.aiConfigs : noteworthyConfigs;
    const maxName = Math.min(35, Math.max(...configsToShow.map((cc) => cc.file.length)));
    for (const config of configsToShow) {
      const fileCol = config.file.padEnd(maxName + 2);
      lines.push(`  ${fileCol}${config.tool}`);
      if (config.risk === 'critical') {
        lines.push(`    ${yellow('Contains hardcoded credentials')} ${dim('—')} ${cyan('opena2a protect .')}`);
      } else if (config.risk === 'high') {
        lines.push(`    ${yellow('Grants broad permissions to AI agents in this project')}`);
      }
    }
    if (!verbose && result.aiConfigs.length > noteworthyConfigs.length) {
      lines.push(`  ${c.dim}+ ${result.aiConfigs.length - noteworthyConfigs.length} low-risk config(s) (run with --verbose to see all)${R}`);
    }
  }

  // ── Next Steps ────────────────────────────────────────────────────
  type Step = { label: string; cmd: string; desc: string };
  const steps: Step[] = [];
  if (result.findings.length > 0) {
    steps.push({ label: 'Full scan:',       cmd: `hackmyagent secure ${targetDir}`, desc: 'deep security scan with findings' });
    if (result.identity.soulFiles === 0 || result.agents.some((a) => a.governanceStatus === 'no governance')) {
      steps.push({ label: 'Add governance:',  cmd: `hackmyagent harden-soul ${targetDir}`, desc: 'generate SOUL.md behavioral boundaries' });
    }
    if (result.aiConfigs.some((cc) => cc.risk === 'critical')) {
      steps.push({ label: 'Protect credentials:', cmd: `opena2a protect ${targetDir}`, desc: 'encrypt hardcoded secrets into secure vault' });
    }
    if (projectMcp.length > 0) {
      steps.push({ label: 'Audit MCP servers:', cmd: 'opena2a mcp audit', desc: 'list servers and verify capability risk' });
    }
  }

  // Always show --help for discoverability
  steps.push({ label: 'All commands:', cmd: 'hackmyagent --help', desc: 'full command reference' });

  lines.push('');
  lines.push(sectionHeader('Next Steps'));
  const maxLabel = Math.max(...steps.map((s) => s.label.length));
  const maxCmd = Math.max(...steps.map((s) => s.cmd.length));
  for (const s of steps) {
    const labelCol = s.label.padEnd(maxLabel + 2);
    const cmdCol = cyan(s.cmd).padEnd(maxCmd + cyan('').length + 2);
    lines.push(`  ${labelCol} ${cmdCol}  ${dim(s.desc)}`);
  }

  lines.push('');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function detect(options: DetectOptions): Promise<number> {
  const dir = path.resolve(options.targetDir ?? process.cwd());

  try {
    fs.accessSync(dir, fs.constants.R_OK);
  } catch {
    process.stderr.write(`Cannot access directory: ${dir}\n`);
    return 1;
  }

  const agents     = scanProcesses();
  const mcpServers = scanMcpServers(dir);
  const identity   = scanIdentity(dir);
  const aiConfigs  = scanAiConfigs(dir);

  identity.totalAgents = agents.length;

  // The authoritative governance measurement (#291). Same scanner, same
  // controls, same number `scan-soul` renders for this directory.
  const soul = await new SoulScanner().scanSoul(dir);

  // Apply governance status from the conformance result.
  //
  // This used to key on `identity.soulFiles > 0` — the mere presence of a
  // file. A SOUL.md holding nothing but prose marked every agent `governed`
  // and printed "All detected AI tools have governance in place" over a
  // document with no controls in it. Presence is not governance.
  //
  // The bar is the soul model's own vocabulary: conformance `none` means one
  // or more CRITICAL governance controls are missing, which is exactly the
  // condition under which an agent is not meaningfully governed. Anything at
  // `essential` or above has its critical controls covered.
  const governanceEstablished = soul.conformance !== 'none';
  if (governanceEstablished) {
    for (const agent of agents) {
      agent.governanceStatus = 'governed';
      agent.risk = 'low';
    }
  }

  // Mark project-local MCP servers that have been scanned by HMA as lower risk
  // (a prior `hackmyagent secure` run passing is implicit approval)
  // For now, all project-local servers stay at their inferred risk level.

  const ungoverned  = agents.filter((a) => a.governanceStatus === 'no governance').length;
  const localLlms   = agents.filter((a) => a.category === 'local-llm').length;

  const result: DetectResult = {
    scanTimestamp:  new Date().toISOString(),
    scanDirectory:  dir,
    summary: {
      totalAgents:      agents.length,
      ungoverned,
      mcpServers:       mcpServers.length,
      localLlms,
      aiConfigs:        aiConfigs.length,
      // Filled in below: the clamp reads the findings, so the findings have
      // to exist first.
      governanceScore:   0,
      governanceRaw:     0,
      governanceClamped: false,
      recoverablePoints: 0,
    },
    agents,
    mcpServers,
    aiConfigs,
    identity,
    findings: [],
  };

  result.findings = generateFindings(result);

  const { governanceScore, governanceRaw, governanceClamped, deductions } =
    reconciledGovernanceScore(soul, result.findings);
  result.summary.governanceScore   = governanceScore;
  result.summary.governanceRaw     = governanceRaw;
  result.summary.governanceClamped = governanceClamped;
  result.summary.recoverablePoints = deductions;

  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(formatText(result, options.verbose ?? false, dir) + '\n');
  }

  if (options.exportCsv) {
    const csv = generateAssetCsv(result);
    fs.writeFileSync(options.exportCsv, csv, 'utf-8');
    process.stdout.write(`Asset inventory: ${options.exportCsv}\n`);
  }

  return 0;
}
