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
    governanceScore: number;
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
    process.argv.includes('--no-color')
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
      if (!fs.existsSync(fullPath)) continue;

      const stats = fs.statSync(fullPath);
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

function calculateGovernanceScore(
  result: Pick<DetectResult, 'agents' | 'mcpServers' | 'aiConfigs' | 'identity'>
): { governanceScore: number; deductions: number } {
  let score = 100;
  let deductions = 0;

  const ungoverned = result.agents.filter((a) => a.governanceStatus === 'no governance');
  const projectMcpCritical = result.mcpServers.filter(
    (s) => s.risk === 'critical' && s.source.includes('(project)')
  );
  const criticalConfigs = result.aiConfigs.filter((c) => c.risk === 'critical');

  // Each ungoverned agent costs 15 pts (capped at 30)
  const agentDeduction = Math.min(30, ungoverned.length * 15);
  score -= agentDeduction;
  deductions += agentDeduction;

  // No SOUL.md when agents present: -15
  if (result.identity.soulFiles === 0 && result.agents.length > 0) {
    score -= 15;
    deductions += 15;
  }

  // Each project-local critical MCP: -10 (capped at 30)
  const mcpDeduction = Math.min(30, projectMcpCritical.length * 10);
  score -= mcpDeduction;
  deductions += mcpDeduction;

  // Credentials in AI configs: -20
  if (criticalConfigs.length > 0) {
    score -= 20;
    deductions += 20;
  }

  return { governanceScore: Math.max(0, score), deductions };
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
    findings.push({
      severity: 'medium',
      category: 'mcp',
      title: `${projectUnverified.length} project MCP server${projectUnverified.length !== 1 ? 's' : ''} without a security scan`,
      detail: projectUnverified.map((s) => s.name).join(', '),
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
        + 'Anyone with repository access can see and use these credentials. '
        + 'Moving them to environment variables limits exposure.',
      remediation: 'opena2a protect .',
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

function buildGovernanceSummary(result: DetectResult): string {
  const { summary } = result;
  const score = summary.governanceScore;

  if (score === 100) return green('Governance: 100/100 — fully governed');

  const scoreColor = score >= 70 ? green : score >= 40 ? yellow : red;
  const projected = Math.min(100, score + summary.recoverablePoints);

  let line = `Governance: ${scoreColor(`${c.bold}${score}${R}`)}/100`;
  if (result.findings.length > 0 && projected > score) {
    line += ` -> ${green(`${c.bold}${projected}${R}`)}/100 by addressing ${result.findings.length} finding${result.findings.length !== 1 ? 's' : ''}`;
  }
  return line;
}

function buildSummaryLine(result: DetectResult): string {
  const { summary } = result;
  const parts: string[] = [];

  if (summary.totalAgents === 0 && summary.mcpServers === 0 && summary.aiConfigs === 0) {
    return dim('No AI agents, MCP servers, or AI configs detected.');
  }

  if (summary.totalAgents > 0) parts.push(`${bold(String(summary.totalAgents))} AI agent${summary.totalAgents !== 1 ? 's' : ''}`);
  if (summary.mcpServers > 0)  parts.push(`${bold(String(summary.mcpServers))} MCP server${summary.mcpServers !== 1 ? 's' : ''}`);
  if (summary.aiConfigs > 0)   parts.push(`${bold(String(summary.aiConfigs))} AI config${summary.aiConfigs !== 1 ? 's' : ''}`);
  if (summary.localLlms > 0)   parts.push(`${bold(String(summary.localLlms))} local LLM${summary.localLlms !== 1 ? 's' : ''}`);

  return parts.join(' | ');
}

function buildWhatThisMeans(result: DetectResult): string[] {
  const lines: string[] = [];
  const { summary } = result;

  if (summary.totalAgents === 0 && summary.mcpServers === 0) return lines;

  lines.push(bold('What This Means'));

  if (summary.totalAgents > 0) {
    const governed = summary.totalAgents - summary.ungoverned;
    if (summary.ungoverned === 0) {
      lines.push(`  Your ${summary.totalAgents === 1 ? 'AI agent has' : 'AI agents have'} `
        + `governance in place. Actions are bounded by the rules you defined.`);
    } else if (governed > 0) {
      lines.push(`  ${summary.totalAgents} AI tool${summary.totalAgents !== 1 ? 's are' : ' is'} running on this machine. `
        + `${governed} ${governed === 1 ? 'has' : 'have'} governance rules, `
        + `${summary.ungoverned} ${summary.ungoverned === 1 ? 'does' : 'do'} not.`);
    } else {
      lines.push(`  ${summary.totalAgents} AI tool${summary.totalAgents !== 1 ? 's are' : ' is'} running `
        + `without governance. No documented rules limit what `
        + `${summary.totalAgents === 1 ? 'it' : 'they'} can do in this project.`);
    }
  }

  if (summary.mcpServers > 0) {
    lines.push(`  ${summary.mcpServers} MCP server${summary.mcpServers !== 1 ? 's give' : ' gives'} your AI agents `
      + `additional capabilities (file access, database queries, API calls, etc.).`);
  }

  lines.push('');
  return lines;
}

function formatText(result: DetectResult, verbose: boolean, targetDir: string): string {
  const lines: string[] = [];

  lines.push(bold('Shadow AI Audit'));
  lines.push(dim(`${os.hostname()} | ${os.userInfo().username} | ${targetDir}`));
  lines.push(dim(result.scanTimestamp.replace('T', ' ').replace(/\.\d+Z$/, ' UTC')));
  lines.push('');

  lines.push(buildGovernanceSummary(result));
  lines.push(buildSummaryLine(result));
  lines.push('');

  lines.push(...buildWhatThisMeans(result));

  // Findings
  if (result.findings.length > 0) {
    lines.push(bold(`Findings (${result.findings.length})`));
    for (const finding of result.findings) {
      lines.push('');
      lines.push(`  ${riskLabel(finding.severity)}  ${finding.title}`);
      if (finding.detail) {
        lines.push(`  ${dim(finding.detail)}`);
      }
      lines.push(`  ${finding.whyItMatters}`);
      lines.push(`  ${dim('Fix:')} ${cyan(finding.remediation)}`);
    }
    lines.push('');
  } else {
    lines.push(green('All detected AI tools have governance in place. No findings.'));
    lines.push('');
  }

  // Running AI Agents
  const assistants = result.agents.filter((a) => a.category === 'ai-assistant');
  const llms       = result.agents.filter((a) => a.category === 'local-llm');

  lines.push(bold('Running AI Agents'));
  if (assistants.length === 0 && llms.length === 0) {
    lines.push(dim('  No AI agents detected'));
  } else {
    for (const agent of [...assistants, ...llms]) {
      const nameCol  = agent.name.padEnd(22);
      const govStr   = agent.governanceStatus === 'governed' ? green('governed') : yellow('ungoverned');
      const pidStr   = verbose ? dim(` (PID ${agent.pid})`) : '';
      lines.push(`  ${nameCol}${govStr}${pidStr}`);
    }
  }
  lines.push('');

  // MCP Servers
  const projectMcp = result.mcpServers.filter((s) => s.source.includes('(project)'));
  const globalMcp  = result.mcpServers.filter((s) => !s.source.includes('(project)'));
  const mcpCount   = result.mcpServers.length;

  lines.push(bold(`MCP Servers (${mcpCount} found)`));
  if (mcpCount === 0) {
    lines.push(dim('  No MCP server configurations found'));
  } else {
    if (projectMcp.length > 0) {
      lines.push(`  ${bold('Project-local')} (${projectMcp.length})`);
      const riskOrder: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      projectMcp.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);
      for (const server of projectMcp) {
        const nameCol = server.name.padEnd(20);
        const riskStr = riskColor(server.risk)(server.risk.toUpperCase());
        const realCaps = server.capabilities.filter((cap) => cap !== 'unknown');
        const capsStr = realCaps.length > 0
          ? dim(` — ${realCaps.map((cap) => capabilityDescription(cap).toLowerCase()).join(', ')}`)
          : '';
        lines.push(`    ${nameCol}${riskStr}${capsStr}`);
      }
    }

    if (globalMcp.length > 0) {
      if (verbose) {
        lines.push(`  ${bold('Machine-wide')} (${globalMcp.length})`);
        for (const server of globalMcp) {
          const nameCol  = server.name.padEnd(20);
          const realCaps = server.capabilities.filter((cap) => cap !== 'unknown');
          const capsStr  = realCaps.length > 0
            ? dim(` — ${realCaps.map((cap) => capabilityDescription(cap).toLowerCase()).join(', ')}`)
            : '';
          lines.push(`    ${nameCol}${capsStr}`);
        }
      } else {
        const sensitiveCaps = globalMcp.filter(
          (s) => s.capabilities.some((cap) => ['shell-access', 'database', 'payments', 'cloud-services'].includes(cap))
        );
        let globalLine = `  ${dim(`Machine-wide (${globalMcp.length})`)}`;
        if (sensitiveCaps.length > 0) {
          const names = sensitiveCaps.map((s) => s.name).join(', ');
          globalLine += dim(` — ${sensitiveCaps.length} with sensitive access: ${names}`);
        }
        lines.push(globalLine);
        lines.push(dim('    Run with --verbose to see full list'));
      }
    }
  }
  lines.push('');

  // AI Config Files (only noteworthy by default)
  const noteworthyConfigs = result.aiConfigs.filter((cc) => cc.risk !== 'low');
  if (result.aiConfigs.length > 0 && (noteworthyConfigs.length > 0 || verbose)) {
    lines.push(bold(`AI Config Files (${result.aiConfigs.length} found)`));
    const configsToShow = verbose ? result.aiConfigs : noteworthyConfigs;
    for (const config of configsToShow) {
      const fileCol = config.file.padEnd(35);
      lines.push(`  ${fileCol}${config.tool}`);
      if (config.risk === 'critical') {
        lines.push(`    ${yellow('Contains hardcoded credentials — run: opena2a protect .  to encrypt into secure vault')}`);
      } else if (config.risk === 'high') {
        lines.push(`    ${yellow('Grants broad permissions to AI agents in this project')}`);
      }
    }
    if (!verbose && result.aiConfigs.length > noteworthyConfigs.length) {
      lines.push(dim(`  + ${result.aiConfigs.length - noteworthyConfigs.length} low-risk config(s) — run with --verbose to see all`));
    }
    lines.push('');
  }

  // Next Steps
  if (result.findings.length > 0) {
    lines.push(bold('Next Steps'));
    lines.push(`  ${cyan('hackmyagent secure .')}             Full project security scan`);
    lines.push(`  ${cyan('hackmyagent harden-soul .')}        Add SOUL.md behavioral governance`);
    if (result.aiConfigs.some((cc) => cc.risk === 'critical')) {
      lines.push(`  ${cyan('opena2a protect .')}               Migrate credentials to environment variables`);
    }
    if (result.mcpServers.some((s) => s.source.includes('(project)'))) {
      lines.push(`  ${cyan('opena2a mcp audit')}               Audit and sign project MCP servers`);
    }
    lines.push('');
  }

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

  // Apply governance status from scanned identity
  if (identity.soulFiles > 0 || identity.capabilityPolicies > 0) {
    for (const agent of agents) {
      agent.governanceStatus = 'governed';
      agent.risk = 'low';
    }
  }

  // Mark project-local MCP servers that have been scanned by HMA as lower risk
  // (a prior `hackmyagent secure` run passing is implicit approval)
  // For now, all project-local servers stay at their inferred risk level.

  const { governanceScore, deductions } = calculateGovernanceScore({
    agents, mcpServers, aiConfigs, identity,
  });

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
      governanceScore,
      recoverablePoints: deductions,
    },
    agents,
    mcpServers,
    aiConfigs,
    identity,
    findings: [],
  };

  result.findings = generateFindings(result);

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
