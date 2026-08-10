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
import { citationTarget as safeCitationTarget, citationPath } from '../ui/shell-quote';
import { escapePathForDisplay, escapeForDisplay } from '../ui/display-safe';
import { findPermissionGrant } from './permission-grant';
import { deriveCheckVerdict, fullCoverage, unmeasuredBanner, coverageJson, unmeasured, EXIT_UNMEASURED } from '../check/verdict';

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
  /**
   * Where in the file the risk was established, and what said so (#299).
   *
   * Present exactly when `risk` is not `low`. `text` is the matched line,
   * redacted and length-capped, and is populated for a permission grant only —
   * the credential branch reports the KEY it matched and never the value, so
   * the report cannot become the place a secret gets copied to.
   */
  evidence?: { line?: number; token: string; text?: string; reason?: string; fix?: string };
}

export interface IdentitySummary {
  soulFiles: number;
  capabilityPolicies: number;
  totalAgents: number;
  /**
   * The governance document `scan-soul` actually measured, or null when
   * there is none (#303).
   *
   * `soulFiles` counts `SOUL.md` alone, while `SoulScanner.GOVERNANCE_FILES`
   * accepts nine names including `CLAUDE.md` and `.cursorrules`. Every
   * consumer that asked `soulFiles === 0` to mean "this project has no
   * governance" was therefore wrong for eight of them, and `detect` printed
   * "No SOUL.md governance file in this project" over a file it had just
   * scored. This is the field to ask instead; `soulFiles` still means what
   * it always meant.
   */
  governanceFile: string | null;
}

export interface Finding {
  severity: RiskLevel;
  category: string;
  title: string;
  detail: string;
  whyItMatters: string;
  remediation: string;
  /**
   * Stable identifier for findings the renderer has to reason about, so it
   * does not have to match on prose. Added for #303: the Path-forward line
   * has to know a governance VIOLATION is outstanding, because that is the
   * one case where adding controls does not move the number.
   */
  code?: 'GOV-VIOLATION' | 'GOV-PROFILE-MARKER';
  /**
   * A command that reproduces the exact trigger this finding cites (#299).
   *
   * Optional because most of `detect`'s findings are about a whole tree — "two
   * agents are ungoverned" has no line to point at, and the house rule is that
   * no Verify beats a Verify that returns something else
   * (`src/ui/verify-command.ts`). It is populated wherever a finding names a
   * `file:line`, and the renderer prints it directly under `Fix:`.
   */
  verify?: string;
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
    /**
     * `scan-soul`'s reported score for the same directory, before `detect`
     * applies the #259 verdict-band clamp on top (#291).
     *
     * NOT a pre-clamp conformance figure, which is what this said. It is
     * `soul.score`, which `scan-soul` has ALREADY clamped for a #206 HIGH
     * (profileMismatch / markerInvalid) or a #251 violation. The pre-clamp
     * average of applicable-domain percentages is `soul.rawScore`, and it can
     * be far higher: a document that carries every control and then subverts
     * one reports rawScore 100 / score 25, and `governanceRaw` is 25.
     *
     * "Raw" is relative to `detect`'s own clamp and means only that — it is
     * the number `scan-soul` prints, so the two surfaces can be compared
     * without `detect`'s host- and project-level findings in the way (#303).
     */
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

/**
 * Set when the last `scanProcesses()` call could not read the process list.
 *
 * Module-scoped rather than a return-shape change because `scanProcesses` is
 * exported and called from tests and other surfaces; the caller that needs it
 * reads it immediately after the call, on the same synchronous path.
 */
let processScanFailed = false;

/** Whether the last `scanProcesses()` call failed to read the process list. */
export function didProcessScanFail(): boolean {
  return processScanFailed;
}

export function scanProcesses(psOutput?: string): DetectedAgent[] {
  processScanFailed = false;
  let output: string;
  if (psOutput !== undefined) {
    output = psOutput;
  } else {
    try {
      output = execSync('ps aux', { encoding: 'utf-8', timeout: 5000 });
    } catch {
      // The process surface could not be read. Returning `[]` here is
      // indistinguishable from "looked and found nothing", and a caller that
      // counts this as an examined surface reports a measured PASS over a
      // surface it never saw — the exact pathology `Coverage` exists to
      // prevent. `processScanFailed` is how the caller tells the difference.
      processScanFailed = true;
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

/**
 * A credential assignment inside an AI config file.
 *
 * Unchanged from the inline version it replaces — hoisted so the line that
 * matched can be located as well as tested for (#299), and so the two config
 * risk levels are established by two named rules rather than by two anonymous
 * literals in a branch.
 */
const CREDENTIAL_IN_CONFIG = /(api[_-]?key|secret|token|password)\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}/i;

/**
 * The first line matching `pattern`, reported as the KEY that matched rather
 * than the value.
 *
 * The value is the credential. A finding that quoted it would print a live
 * secret to the terminal and into any log capturing the run, so the report
 * carries the location and the key name and stops there — `text` is left unset
 * and the renderer has nothing to quote.
 */
function firstMatchLine(content: string, pattern: RegExp): { line: number; token: string } | undefined {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = pattern.exec(lines[i]);
    if (m) return { line: i + 1, token: m[1] ?? m[0] };
  }
  return undefined;
}

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
      let evidence: AiConfigFile['evidence'];

      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        const credential = firstMatchLine(content, CREDENTIAL_IN_CONFIG);
        // Only one of the two is reported, and the credential outranks the
        // grant — so the grant scan is skipped rather than computed and
        // discarded.
        // `file` selects the parsed half from the prose half (#364), so it is
        // the config's own name rather than the absolute path: the extension is
        // all that is read, and a temp-dir prefix has no business in it.
        const grant = credential ? undefined : findPermissionGrant(content, file);

        if (credential) {
          risk = 'critical';
          details = `${pattern.tool} config contains credential references`;
          evidence = credential;
        } else if (grant) {
          risk = 'high';
          details = `${pattern.tool} config grants broad permissions`;
          evidence = {
            line: grant.line,
            token: grant.token,
            text: grant.text,
            reason: grant.reason,
            fix: grant.fix,
          };
        }
      } catch { /* file unreadable */ }

      configs.push({ file, tool: pattern.tool, risk, details, evidence });
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

  // `governanceFile` is filled in by the caller, which has the SoulScanner
  // result. `scanIdentity` deliberately stays a pure filesystem probe.
  return { soulFiles, capabilityPolicies, totalAgents: 0, governanceFile: null };
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

/**
 * How this scan should name its target inside a fix citation (#293, second
 * pass — `detect`).
 *
 * `detect`'s remediation strings were hardcoded to a bare `.`, so scanning
 * one tree from another directory printed
 *
 *   Fix: hackmyagent harden-soul .
 *
 * and pasting it generated a SOUL.md in the CURRENT directory rather than the
 * one that was scanned — writing to the wrong tree while reporting success,
 * which is the harm #293 was filed over. `secure` was fixed there; `detect`
 * builds these strings itself and never reached the rewriter, which
 * deliberately leaves an explicit `.` alone because for every other command a
 * `.` really does mean the scanned tree.
 *
 * Kept pathless when the scan target IS the working directory, so the common
 * case stays free of churn.
 *
 * #339 — and it is sanitised HERE, at the one place the target enters `detect`'s
 * citation layer, for the reason #328 gives for doing it at the entry point
 * rather than at each consumer: there are four of them, and fixing the ones that
 * were noticed is how six injectable citations survived a change named for this
 * property. Measured on the previous build, with a directory named
 * `pwn.txt'; touch PWNED; echo '<LF>EVIL-SECOND-LINE<ESC>[2Jcleared`, `detect`
 * emitted six pasteable `; touch PWNED;` citations, six raw control bytes and
 * six split lines. A target that cannot be both shown and pasted becomes the
 * house `<dir>` placeholder rather than a command naming bytes the reader cannot
 * see.
 */
function citationTarget(scanDirectory: string): string {
  try {
    return path.resolve(scanDirectory) === path.resolve(process.cwd())
      ? '.'
      : safeCitationTarget(scanDirectory);
  } catch {
    return safeCitationTarget(scanDirectory);
  }
}

/**
 * The cause split every governance surface cites from (#303/#307).
 *
 * `harden-soul` adds control text. That fixes a document that is absent or
 * incomplete, and it cannot touch a sentence that subverts a control or a
 * broken profile marker — so citing it on a subverted document is a dead end:
 * the command runs, changes nothing relevant, and the score does not move.
 * Those go to `scan-soul`, which lists the offending lines.
 *
 * Written once and derived from the finding CODES so the renderer and the
 * finding generator cannot drift apart. `GOV-VIOLATION` is emitted exactly
 * when there are violations and `GOV-PROFILE-MARKER` exactly when the marker
 * is mismatched or unrecognized, which is the same condition
 * `generateFindings` computes from `soul` directly — `governance-cross-surface`
 * pins the two against each other.
 */
export function governanceIsSubverted(findings: readonly Pick<Finding, 'code'>[]): boolean {
  return findings.some((f) => f.code === 'GOV-VIOLATION' || f.code === 'GOV-PROFILE-MARKER');
}

/**
 * The three causes a governance score can have, and everything each surface says
 * about them, in ONE place.
 *
 * #322 — #311 claimed the surfaces "cannot promise different things" because they
 * read one predicate. They shared the AVAILABILITY predicate and not the CAUSE
 * predicate: Path forward split on `GOV-VIOLATION` alone, while the step label
 * and command went through `governanceIsSubverted`, which also matches
 * `GOV-PROFILE-MARKER`. On a document whose only problem is an unrecognized
 * marker, four consecutive lines said:
 *
 *   Path forward: 74 -> 100 by adding the missing governance controls
 *   Fix governance:  hackmyagent scan-soul <dir>   list the sentences that subvert your own controls
 *
 * The first promises `harden-soul`'s effect and offers no command for it; the
 * second describes subverting sentences that do not exist. A malformed marker is
 * neither of the two causes the code knew about, so it got the wrong half of
 * each.
 *
 * `pathForward` is a phrase, not a sentence, because the caller joins several
 * with "and".
 */
export type GovernanceCause = 'subverted' | 'profile-marker' | 'incomplete';

interface GovernanceStep {
  label: string;
  command: (target: string) => string;
  desc: string;
  pathForward: string;
}

const GOVERNANCE_STEPS: Record<GovernanceCause, GovernanceStep> = {
  // `harden-soul` adds control text and cannot delete a sentence, so the command
  // is the one that LISTS the sentences to delete.
  subverted: {
    label: 'Fix governance:',
    command: (target) => `hackmyagent scan-soul ${target}`,
    desc: 'list the sentences that subvert your own controls',
    pathForward: 'removing the sentences that subvert your own controls',
  },
  // Also `scan-soul`, and for a different reason: it is what reports which
  // domains the marker caused to be skipped. `harden-soul` would add controls
  // that are already there, and "remove the subverting sentences" names lines
  // that do not exist.
  'profile-marker': {
    label: 'Fix governance:',
    command: (target) => `hackmyagent scan-soul ${target}`,
    desc: 'show which governance domains the profile marker skipped',
    pathForward: 'correcting the profile marker so every domain is evaluated',
  },
  incomplete: {
    label: 'Add governance:',
    command: (target) => `hackmyagent harden-soul ${target}`,
    desc: 'generate SOUL.md behavioral boundaries',
    pathForward: 'adding the missing governance controls',
  },
};

/**
 * The cause, from the finding codes plus the raw conformance number. Null when
 * the governance meter is full and nothing is wrong with the document, which is
 * the one case where no surface owes the user anything.
 *
 * Precedence is deliberate: a document that both subverts a control and carries a
 * bad marker is described by the more serious of the two, and the marker case is
 * only reached when there are no violations to remove.
 */
export function governanceCause(
  findings: readonly Pick<Finding, 'code'>[],
  governanceRaw: number,
): GovernanceCause | null {
  if (findings.some((f) => f.code === 'GOV-VIOLATION')) return 'subverted';
  if (findings.some((f) => f.code === 'GOV-PROFILE-MARKER')) return 'profile-marker';
  if (governanceRaw < 100) return 'incomplete';
  return null;
}

/**
 * The same cause, derived from the scan signals instead of from the findings.
 *
 * `generateFindings` runs BEFORE any finding exists, so it cannot use
 * `governanceCause` — and two independent derivations of one predicate drift,
 * which is what #322 was. Both now come from this table, and
 * `governance-cross-surface` pins them against each other on every fixture.
 */
export function governanceCauseFromSignals(signals: {
  violations: number;
  profileBad: boolean;
  incomplete: boolean;
}): GovernanceCause | null {
  if (signals.violations > 0) return 'subverted';
  if (signals.profileBad) return 'profile-marker';
  if (signals.incomplete) return 'incomplete';
  return null;
}

/**
 * The command that can actually move a governance score, given the cause.
 *
 * Defaults to `incomplete` when there is no cause: the only caller that can
 * reach that state is one rendering a step it has already decided to show, and
 * `harden-soul` is the honest default for "the document could carry more".
 */
export function governanceRemediation(
  findings: readonly Pick<Finding, 'code'>[],
  target: string,
): string {
  const cause = governanceCause(findings, 0) ?? 'incomplete';
  return GOVERNANCE_STEPS[cause].command(target);
}

/**
 * The label that matches the command. `Add governance:` over a `scan-soul`
 * citation described neither the cause nor the effect: nothing is being added,
 * the controls are already there and one of them is being contradicted.
 */
export function governanceStepLabel(findings: readonly Pick<Finding, 'code'>[]): string {
  return GOVERNANCE_STEPS[governanceCause(findings, 0) ?? 'incomplete'].label;
}

/** What the cited command will do, in the user's words rather than ours. */
export function governanceStepDescription(findings: readonly Pick<Finding, 'code'>[]): string {
  return GOVERNANCE_STEPS[governanceCause(findings, 0) ?? 'incomplete'].desc;
}

/**
 * The phrase Path forward attributes the recoverable points to. Same cause, same
 * table, so the promise and the command cannot describe different work.
 */
export function governancePathForwardPhrase(
  findings: readonly Pick<Finding, 'code'>[],
  governanceRaw: number,
): string | null {
  const cause = governanceCause(findings, governanceRaw);
  return cause ? GOVERNANCE_STEPS[cause].pathForward : null;
}

/**
 * True when the governance meter still has room to move, so Next Steps owes the
 * user a command for it.
 *
 * #311 — this was `identity.governanceFile === null`, which is null only when
 * NO governance document exists at all. A prose-only `CLAUDE.md` scoring 0/100
 * therefore got no governance step, while the Path forward line one screen up
 * was still promising `0 -> 100 by adding the missing governance controls`. A
 * promise with no command is the dead end this project's own rule forbids, and
 * `harden-soul` is exactly right there — it APPENDS missing sections to an
 * existing document.
 *
 * Deliberately host-independent. The step previously survived only via a second
 * disjunct, "some agent is ungoverned", which comes from `ps`: on CI, or any
 * machine not currently running an AI process, a 0/100 meter was a dead end.
 * That disjunct is also subsumed — full conformance with no subversion is what
 * marks every agent `governed` — so dropping it costs no coverage.
 *
 * Same inputs as the Path forward line by construction, so the two surfaces
 * cannot promise different things.
 */
export function governanceActionAvailable(
  findings: readonly Pick<Finding, 'code'>[],
  governanceRaw: number,
): boolean {
  // Availability is "there is a cause", so it reads the same function the label,
  // the command, the description and the Path forward phrase read (#322). The
  // previous `subverted || raw < 100` was equivalent, and being equivalent is
  // exactly how the cause split drifted while the availability gate did not.
  return governanceCause(findings, governanceRaw) !== null;
}

/**
 * A scanned string as it should appear inside report prose, in quotes (#299).
 *
 * The value comes out of the user's tree, so it is display-escaped before it
 * reaches a line — a `.cursorrules` carrying an ESC byte or a bidi override
 * could otherwise repaint the report around it, which is #324 with a new
 * source. Quoting is plain `"` because this is prose to read, not a command to
 * paste; nothing here is spliced into a shell.
 */
function quoted(s: string): string {
  const escaped = escapeForDisplay(s);
  // A structured grant already arrives quoted — the token that matched in
  // `.claude/settings.json` is literally `"Bash(*)"`, and wrapping it again
  // printed `""Bash(*)""`.
  return /^".*"$/s.test(escaped) ? escaped : `"${escaped}"`;
}

/**
 * `<file>:<line> — matched "<phrase>"`, the shape the house finding standard
 * asks for (#299), plus a count of any further files with the same problem.
 *
 * Falls back to the old filename list when a config carries no evidence, which
 * is unreachable for the two callers (both filter on a non-`low` risk, and risk
 * is only raised alongside evidence) and is here so the renderer degrades to
 * the previous output rather than to `undefined:undefined` if that ever stops
 * being true.
 */
function configEvidenceDetail(configs: readonly AiConfigFile[]): string {
  const head = configs[0];
  if (!head?.evidence) return configs.map((cc) => cc.file).join(', ');
  // `:line` only when the detector could cite one safely — a structured
  // config that also declares a restriction key gets the file alone, because
  // locating an entry by text there can land on the DENY line.
  const at = head.evidence.line === undefined ? '' : `:${head.evidence.line}`;
  const where = `${escapePathForDisplay(head.file)}${at}`;
  // The TOKEN, not the line. The claim is "this phrase grants broad
  // permissions", so the phrase is what the finding has to show; the whole line
  // is what the Verify command prints, and it stays on `evidence.text` for a
  // `--json` consumer that wants it without re-reading the file.
  const what = head.evidence.token;
  const rest = configs.length - 1;
  const more = rest > 0 ? ` (+${rest} more config file${rest > 1 ? 's' : ''})` : '';
  // "matched" is the honest verb for the prose half and the wrong one for the
  // parsed half — nothing was matched there, the permission key was read (#364).
  // The reason says which of the two produced this and why it is a grant.
  const why = head.evidence.reason ? ` ${head.evidence.reason}` : '';
  const verb = head.evidence.reason ? '' : 'matched ';
  return `${where} — ${verb}${quoted(what)}${why}${more}`;
}

/**
 * `sed -n '<line>p' <file>` for a cited config, or undefined when the path
 * cannot be named truthfully.
 *
 * Kept as its own function, but the paths have partly converged: #286 gave
 * `generateVerifyCommand()` an optional `scanRoot`, and on that path it joins
 * the root to the finding's file and renders through `citationPath` — which,
 * unlike `shellEscapePath`, also makes a leading `-` an operand. That much this
 * comment used to point forward to.
 *
 * THE RULE IS THE SAME ON BOTH: NO LINE, NO VERIFY. An earlier revision of this
 * function kept a `cat <path>` branch for the lineless case and argued it was
 * safe here because this function "fires only on an `AiConfigFile` ... where the
 * file is a declarative agent config rather than a secret store". That claim was
 * false, and one run falsified it: a `.claude/settings.json` holding
 * `permissions.allow: ["Bash(*)"]` alongside an `env` block is BOTH, and it is
 * the ordinary shape of that file. `detect` rendered
 *
 *     HIGH  AI config files grant broad permissions
 *     Verify: cat <target>/.claude/settings.json
 *
 * while `secure` reported `CRITICAL Exposed Credential` on the same file — the
 * tool telling the reader to print a secret file it had itself flagged as
 * holding one. That is the exact defect `generateVerifyCommand` deleted, and it
 * survived here because the sweep was done by spelling rather than by class.
 *
 * `cat` also never verified the flagged trigger. The finding is about a
 * permission ENTRY; `cat` prints the whole file and leaves the reader to find
 * it. So it failed the standard's item 3 independently of the disclosure.
 *
 * The lineless case now emits nothing. The finding keeps its `fix`, and the
 * absent Verify is the signal that the emit site owes a line: the structured
 * permission path (`permission-grant.ts` `findPermissionGrant`) deliberately
 * returns none, which is tracked separately — recovering it there is what turns
 * this back into a `sed`, and it is the only thing that should.
 */
function configVerifyCommand(scanDirectory: string, config: AiConfigFile | undefined): string | undefined {
  if (!config?.evidence) return undefined;
  if (config.evidence.line === undefined) return undefined;
  const quotedPath = citationPath(path.join(scanDirectory, config.file));
  if (!quotedPath) return undefined;
  return `sed -n '${config.evidence.line}p' ${quotedPath}`;
}

function generateFindings(result: Omit<DetectResult, 'findings'>, soul: SoulScanResult): Finding[] {
  const findings: Finding[] = [];
  const target = citationTarget(result.scanDirectory);
  const violations = soul.violations ?? [];
  /**
   * The governance document is present and actively working against itself,
   * as opposed to merely incomplete. This is the distinction that decides
   * which command to cite: `harden-soul` adds control text, which fixes
   * incompleteness and cannot touch any of these.
   *
   * The codes below are emitted under exactly these conditions, which is what
   * lets the renderer reach the same verdict from the findings alone — see
   * `governanceIsSubverted`.
   */
  // #322 — the CAUSE, not a boolean. `incomplete: true` is the fallback because
  // the only finding that consumes this is raised when the document is already
  // inadequate, so "nothing is wrong" is not a reachable state here.
  const cause = governanceCauseFromSignals({
    violations: violations.length,
    profileBad: Boolean(soul.profileMismatch) || Boolean(soul.markerInvalid),
    incomplete: true,
  }) ?? 'incomplete';
  const isSubverted = cause !== 'incomplete';

  // Ungoverned agents
  const ungoverned = result.agents.filter((a) => a.governanceStatus === 'no governance');
  if (ungoverned.length > 0) {
    // #303 — the reason has to travel with the verdict, and it has to be the
    // real one. This read `no SOUL.md governance file found` whenever
    // `identity.soulFiles === 0`, but `identity` counts only `SOUL.md` while
    // `SoulScanner.GOVERNANCE_FILES` also accepts `CLAUDE.md`,
    // `.cursorrules`, `system-prompt.md` and six more. A project governed
    // through a `CLAUDE.md` was therefore told its agents were ungoverned
    // because no file existed, over a file the scanner had just read and
    // scored. Name the document that was actually measured, and say what is
    // wrong with it — `harden-soul` cannot remove a violation, so pointing
    // there without that sentence is a dead end.
    const reasons: string[] = [];
    if (!soul.file) reasons.push('no governance file found');
    else if (soul.criticalMissing.length > 0) {
      reasons.push(`${soul.file} is missing ${soul.criticalMissing.length} critical control(s)`);
    }
    if (violations.length > 0) {
      reasons.push(`${soul.file} contains ${violations.length} governance violation(s)`);
    }
    if (soul.profileMismatch) reasons.push(`${soul.file} declares a narrower profile than its content`);
    if (soul.markerInvalid) reasons.push(`${soul.file} carries an unrecognized profile marker`);

    const detail = ungoverned.map((a) => a.name).join(', ')
      + (reasons.length > 0 ? ` — ${reasons.join('; ')}` : '');
    findings.push({
      severity: 'high',
      category: 'governance',
      title: `${ungoverned.length} AI agent${ungoverned.length !== 1 ? 's' : ''} running without governance`,
      detail,
      whyItMatters:
        'These agents can take actions in your project but have no rules defining what they '
        + 'should or should not do. A SOUL.md file sets behavioral boundaries — what agents can and '
        + 'cannot do, and what requires human approval.',
      // `harden-soul` both CREATES a governance document and appends missing
      // sections to an existing one, so it is the right command for "no file"
      // and for "file missing controls" alike. It is the wrong command for
      // the substance failures: no amount of added control text removes a
      // sentence that subverts one, or repairs a profile marker. Those go to
      // `scan-soul`, which lists the offending sentences with line numbers.
      remediation: GOVERNANCE_STEPS[cause].command(target),
    });
  }

  // #303 — the three substance signals `detect` used to drop. `scan-soul`
  // clamps its score for each of these; rendering the clamped number without
  // them left the user a lower score and no way to find out why.
  if (violations.length > 0) {
    const first = violations.slice(0, 3);
    findings.push({
      severity: 'high',
      category: 'governance',
      code: 'GOV-VIOLATION',
      // Partitive: "N of its own controls" takes the plural at every N,
      // including 1 — the noun describes the SET being drawn from, not the
      // count drawn. "subverts 1 of its own control" is ungrammatical.
      title: `Governance document subverts ${violations.length} of its own controls`,
      detail: first
        .map((v) => `${soul.file}:${v.line} ${v.name} (${v.controlId})`)
        .join('; ')
        + (violations.length > first.length ? `; +${violations.length - first.length} more` : ''),
      whyItMatters:
        'These are not controls the document is missing — they are sentences that instruct the '
        + 'agent to do the opposite of what the control requires, such as complying with override '
        + 'requests or concealing its reasoning. A document like this scores as governance while '
        + 'removing it, so adding more controls does not help; the sentences have to go.',
      remediation: `hackmyagent scan-soul ${target}`,
    });
  }

  if (soul.profileMismatch || soul.markerInvalid) {
    const isInvalid = Boolean(soul.markerInvalid);
    findings.push({
      severity: 'medium',
      category: 'governance',
      code: 'GOV-PROFILE-MARKER',
      title: isInvalid
        ? 'Governance document carries an unrecognized profile marker'
        : 'Governance document declares a narrower profile than its content',
      detail: `${soul.file}`,
      whyItMatters:
        'The profile marker decides which governance domains are evaluated. A marker that is '
        + 'narrower than the document, or that names nothing the scanner recognizes, means whole '
        + 'domains were skipped rather than passed — so the score describes less of the document '
        + 'than it appears to.',
      remediation: `hackmyagent scan-soul ${target}`,
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
      remediation: `hackmyagent secure ${target}`,
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
      remediation: `hackmyagent secure ${target}`,
    });
  }

  // Credentials in AI config files
  const criticalConfigs = result.aiConfigs.filter((c) => c.risk === 'critical');
  if (criticalConfigs.length > 0) {
    findings.push({
      severity: 'critical',
      category: 'config',
      title: 'AI config files contain credential references',
      detail: configEvidenceDetail(criticalConfigs),
      whyItMatters:
        'API keys or tokens appear to be stored directly in these configuration files. '
        + 'Anyone with repository access can see and use these credentials.',
      remediation: `opena2a protect ${target}  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.`,
      verify: configVerifyCommand(result.scanDirectory, criticalConfigs[0]),
    });
  }

  // Broad permissions in AI configs
  //
  // #299 — the detail, the fix and the Verify all name the phrase that
  // triggered this. The previous version named the FILE and cited `scan-soul`,
  // which measures governance conformance and cannot tell anyone which
  // permission to remove: a reader who ran it got a different report about a
  // different question, which is a topic change rather than a remedy.
  const highConfigs = result.aiConfigs.filter((c) => c.risk === 'high');
  if (highConfigs.length > 0) {
    const cited = highConfigs[0];
    findings.push({
      severity: 'high',
      category: 'config',
      title: 'AI config files grant broad permissions',
      detail: configEvidenceDetail(highConfigs),
      whyItMatters:
        'These configs allow AI agents to perform a wide range of actions without restrictions. '
        + 'Broad permissions increase risk if an agent behaves unexpectedly.',
      // The fix comes from the vocabulary that classified the entry, because
      // the generic sentence is wrong for half of them: "replace it with the
      // specific commands or paths this agent needs" is a dead end against
      // `defaultMode: acceptEdits`, which takes neither a command nor a path.
      remediation: cited.evidence
        ? `Narrow ${escapePathForDisplay(cited.file)}${cited.evidence.line === undefined ? '' : `:${cited.evidence.line}`} — ${
          cited.evidence.fix
            ?? `replace ${quoted(cited.evidence.token)} with the specific commands or paths this agent needs`
        }`
        : `hackmyagent scan-soul ${target}`,
      verify: configVerifyCommand(result.scanDirectory, cited),
    });
  }

  // No SOUL.md when agents present but no ungoverned finding yet.
  //
  // #303 — gated on `soul.file`, not on `identity.soulFiles`. `identity`
  // counts `SOUL.md` alone, so a project governed through a `CLAUDE.md` got
  // "No SOUL.md governance file in this project" printed directly beneath
  // "All detected AI tools have governance in place", each half of the same
  // output contradicting the other about whether governance exists.
  if (!soul.file && result.agents.length > 0 && ungoverned.length === 0) {
    findings.push({
      severity: 'medium',
      category: 'governance',
      title: 'No SOUL.md governance file in this project',
      detail: 'Agents are governed by capability policies but have no SOUL.md behavioral boundaries.',
      whyItMatters:
        'A SOUL.md file defines what an agent should and should not do beyond capability restrictions — '
        + 'handling errors, sensitive data, and when to ask for human approval.',
      remediation: `hackmyagent harden-soul ${target}`,
    });
  }

  // The governance document lives somewhere other than SOUL.md. Not a
  // failure — `SoulScanner` accepts nine filenames and scored this one — but
  // the tool's own remediation, its docs and `harden-soul` all write
  // `SOUL.md`, so a reader has to be told which file the number came from.
  if (soul.file && soul.file !== 'SOUL.md' && result.agents.length > 0) {
    findings.push({
      severity: 'low',
      category: 'governance',
      title: `Governance is defined in ${soul.file}, not SOUL.md`,
      detail: `The Governance score above was measured against ${soul.file}.`,
      whyItMatters:
        'This is a supported location, so nothing is broken. It is worth knowing because every '
        + 'other surface of this tool — harden-soul, the docs, the fix commands — refers to '
        + 'SOUL.md, and a reader looking for the file the score came from would not find it.',
      remediation: `hackmyagent scan-soul ${target}`,
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

function formatText(result: DetectResult, verbose: boolean, rawTargetDir: string): string {
  const lines: string[] = [];
  const { summary } = result;
  // #339 — `targetDir` is a path out of the scanned tree and every Next Step
  // below splices it into a command the reader is told to paste. Sanitised ONCE
  // here, at the entry to this renderer, rather than at each of the four
  // consumers: fixing the consumers that were noticed is exactly how six
  // injectable citations survived a change named for this property.
  const targetDir = safeCitationTarget(rawTargetDir);
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
  // The header is DISPLAY, not a command, so it takes the path escaping rather
  // than the citation form — a basename that carries a newline split this line
  // and put the attacker's second line above the report's own metadata.
  const dirBase = escapePathForDisplay(path.basename(rawTargetDir) || rawTargetDir);
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
      if (f.verify) lines.push(`  ${pipe} ${c.dim}Verify:${R} ${dim(f.verify)}`);
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
    // #303 — a violation is not a missing control, and `harden-soul` cannot
    // remove one. On a document that carries every control and then subverts
    // one, this line read `25 -> 100 by adding the missing governance
    // controls` while the 75 lost points came entirely from the #251
    // violation clamp: every control it names was already present. Name the
    // sentences instead, since deleting them is what moves the number.
    //
    // #322 — and the split has to be the SAME one the Next Steps command comes
    // from. This read `hasViolation ? … : raw < 100 ? …`, which put a malformed
    // profile marker in the "missing controls" branch: the line promised
    // `harden-soul`'s effect while the step one screen down cited `scan-soul`,
    // and no command for the promise appeared anywhere.
    const govPhrase = governancePathForwardPhrase(result.findings, summary.governanceRaw);
    if (govPhrase) steps.push(govPhrase);
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
      // #303 — the same citation the ungoverned finding carries, chosen the
      // same way, so the row and the finding cannot disagree. `harden-soul`
      // adds control text; against a document whose problem is a sentence
      // that subverts a control, it is a command with nothing to do.
      // #322 — through the shared cause table rather than a fourth inline copy
      // of the predicate. An inline copy is what drifted.
      const govFix = governanceRemediation(result.findings, citationTarget(result.scanDirectory));
      const fixHint = !isGoverned ? `  ${dim('→')}  ${cyan(govFix)}` : '';
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
      // #299 — the same specificity the finding now carries. "Grants broad
      // permissions to AI agents in this project" was printed under the
      // filename of a document whose text RESTRICTED the agent, and a reader
      // had nothing to check it against.
      // The line is OPTIONAL — a structured config that also declares a
      // restriction key gets no line, because locating an entry by text on such
      // a file can return the deny entry. Interpolating it unguarded printed
      // `line undefined:` here, which is the one surface that reads the field
      // directly rather than through `configEvidenceDetail`.
      const where = config.evidence?.line === undefined ? '' : ` line ${config.evidence.line}`;
      const at = config.evidence ? dim(`${where}: `) + quoted(config.evidence.token) : '';
      if (config.risk === 'critical') {
        lines.push(`    ${yellow('Contains hardcoded credentials')}${at} ${dim('—')} ${cyan('opena2a protect .')}`);
      } else if (config.risk === 'high') {
        lines.push(`    ${yellow('Grants broad permissions')}${at}`);
      }
    }
    if (!verbose && result.aiConfigs.length > noteworthyConfigs.length) {
      lines.push(`  ${c.dim}+ ${result.aiConfigs.length - noteworthyConfigs.length} low-risk config(s) (run with --verbose to see all)${R}`);
    }
  }

  // ── Next Steps ────────────────────────────────────────────────────
  type Step = { label: string; cmd: string; desc: string };
  const steps: Step[] = [];
  // #307 — the THIRD consumer of `identity.soulFiles`, and the one that was
  // missed when the other two were fixed. `soulFiles` counts `SOUL.md` alone,
  // so a project governed by a fully-conformant `CLAUDE.md` was told to
  // `harden-soul` right under a Governance meter reading 100/100 that had just
  // been computed FROM that file.
  //
  // #311 — but "a document exists" was the wrong question too, in the other
  // direction: it is false only when NOTHING exists, so an inadequate but
  // present document lost its step entirely. The question is whether the METER
  // can still move, which is what the Path forward line already answers — so
  // both surfaces read the same predicate and cannot promise different things.
  //
  // Rendered OUTSIDE the findings block, for the same reason the Path forward
  // line is (#291): a tree can sit far below the governance bar with nothing
  // else wrong. On a host with no AI process running there is no ungoverned-
  // agent finding, so the whole block was skipped and a 4/100 meter was left
  // promising "adding the missing governance controls" with no command anywhere
  // in the output. That is the CI condition, not an exotic one.
  //
  // The command and the label come from the shared cause split, so this surface
  // cites what the ungoverned finding cites: `harden-soul` cannot remove a
  // violation, and offering it as the next step on a subverted document is the
  // same dead end one screen lower.
  // Step ORDER is unchanged: `Full scan` stays first where it applies, and the
  // governance step keeps its original position behind it. Only its GATE moved.
  const hasFindings = result.findings.length > 0;
  if (hasFindings) {
    steps.push({ label: 'Full scan:',       cmd: `hackmyagent secure ${targetDir}`, desc: 'deep security scan with findings' });
  }
  // `?? 0`, not `?? 100`: `governanceRaw` is non-optional on the type, so this
  // only fires if a caller ever hands us a partial summary — and the safe
  // direction there is to OFFER the step. Defaulting to 100 would suppress it,
  // which is the dead end #311 exists to remove.
  if (governanceActionAvailable(result.findings, summary.governanceRaw ?? 0)) {
    steps.push({
      label: governanceStepLabel(result.findings),
      cmd: governanceRemediation(result.findings, targetDir),
      // #322 — the description comes from the same cause as the command. It used
      // to be its own two-way `governanceIsSubverted` branch, so a malformed
      // profile marker was described as "the sentences that subvert your own
      // controls" — sentences the document does not contain.
      desc: governanceStepDescription(result.findings),
    });
  }
  if (hasFindings) {
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
    // Unreadable target: nothing was examined, so this is 2 and not 1. Exit 1
    // here would tell a CI consumer `detect` found a high-severity issue in a
    // directory it could not open. This is the only path that reaches the
    // unmeasured arm.
    process.stderr.write(
      `${unmeasuredBanner(unmeasured(
        'target-unreadable',
        `${escapePathForDisplay(dir)} could not be read, so nothing was scanned.`,
      ))}\n`,
    );
    return EXIT_UNMEASURED;
  }

  const agents     = scanProcesses();
  const mcpServers = scanMcpServers(dir);
  const identity   = scanIdentity(dir);
  const aiConfigs  = scanAiConfigs(dir);

  identity.totalAgents = agents.length;

  // The authoritative governance measurement (#291). Same scanner, same
  // controls, same number `scan-soul` renders for this directory.
  const soul = await new SoulScanner().scanSoul(dir);
  // Which document that measurement came from, so no consumer has to infer
  // it from `soulFiles` and get it wrong for the other eight names (#303).
  identity.governanceFile = soul.file;

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
  //
  // #303 — conformance alone is not that bar. `calculateConformance` returns
  // `none` only when a critical control is MISSING, so a document that
  // carries every critical control and then instructs the agent to comply
  // with override requests is `essential`, and every agent was marked
  // `governed` by it:
  //
  //   scan-soul   25/100   conformance essential   1 violation
  //   detect      ungoverned 0/2, zero findings, exit 0
  //               "All detected AI tools have governance in place"
  //
  // `scan-soul` clamps its score for exactly these three signals, and
  // `detect` was rendering the clamped number while ignoring what caused it —
  // consuming the verdict and discarding the evidence. A control that is
  // present and subverted governs nothing, and a profile marker the scanner
  // could not trust means the domains it skipped were never measured at all.
  const violations = soul.violations ?? [];
  const governanceEstablished =
    soul.conformance !== 'none' &&
    violations.length === 0 &&
    !soul.profileMismatch &&
    !soul.markerInvalid;
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

  result.findings = generateFindings(result, soul);

  const { governanceScore, governanceRaw, governanceClamped, deductions } =
    reconciledGovernanceScore(soul, result.findings);
  result.summary.governanceScore   = governanceScore;
  result.summary.governanceRaw     = governanceRaw;
  result.summary.governanceClamped = governanceClamped;
  result.summary.recoverablePoints = deductions;

  // #390 — `detect` printed `1 high-severity issue found` and returned 0, so
  // no CI job could ever fail on a shadow-AI finding. The exit code comes from
  // the same derivation `check` uses, over the same severity counts the
  // verdict line is rendered from, so the two cannot disagree.
  //
  // Derived ABOVE the output-channel branch for the same reason `check`
  // settles there (#373): a `return` inside a renderer must not be able to
  // change the exit code.
  //
  // The coverage unit is the number of DISCOVERY PASSES that ran, not the
  // number of things they found.
  //
  // The first cut summed `agents.length + mcpServers.length + aiConfigs.length`
  // — a count of findings wearing a coverage label. On a host with no AI
  // tooling every term is 0, so the honest answer "I examined four surfaces and
  // found nothing" would have been reported as `NOT MEASURED` at exit 2, which
  // collapses "clean" into "cannot tell" and makes `detect` useless as the
  // no-shadow-AI CI gate it is for. The comment claimed the opposite of what
  // the expression did.
  //
  // COUNTED, not asserted. A constant here was a second bug of the same class
  // as the one it replaced: `scanProcesses` swallows an `execSync('ps aux')`
  // failure and returns `[]`, so on a host without `procps` the constant
  // reported `4 of 4 surfaces examined` and a measured PASS over a surface the
  // run never saw. Measured with `PATH=/nonexistent`: exit 0 and coverage
  // byte-identical to a healthy run. That is fail-open, and the whole point of
  // `Coverage` is that every field is counted at runtime from the run itself.
  const surfaces = [
    { name: 'processes', examined: !didProcessScanFail() },
    { name: 'mcp servers', examined: true },
    { name: 'identity', examined: true },
    { name: 'ai configs', examined: true },
    { name: 'governance', examined: true },
  ];
  const examinedSurfaces = surfaces.filter((s) => s.examined).length;
  const unread = surfaces.filter((s) => !s.examined).map((s) => s.name);
  const verdict = deriveCheckVerdict(
    {
      critical: result.findings.filter((f) => f.severity === 'critical').length,
      high: result.findings.filter((f) => f.severity === 'high').length,
      issues: result.findings.length,
    },
    { examined: examinedSurfaces, total: surfaces.length, unit: 'surface' },
  );
  // A partial read is not an unmeasured run — the other surfaces did produce a
  // verdict — but it must be said out loud, or a reader takes the clean lines
  // for a complete answer.
  if (unread.length > 0 && options.format !== 'json') {
    process.stderr.write(
      `Not examined: ${unread.join(', ')}. This report does not cover ${unread.length === 1 ? 'it' : 'them'}.\n`,
    );
  }

  if (options.format === 'json') {
    // The machine channel carries the measurement the exit code was derived
    // from, so a consumer never has to infer it from the finding count.
    process.stdout.write(JSON.stringify({ ...result, coverage: coverageJson(verdict) }, null, 2) + '\n');
  } else {
    process.stdout.write(formatText(result, options.verbose ?? false, dir) + '\n');
    if (!verdict.measured) process.stderr.write(`${unmeasuredBanner(verdict)}\n`);
  }

  if (options.exportCsv) {
    const csv = generateAssetCsv(result);
    fs.writeFileSync(options.exportCsv, csv, 'utf-8');
    process.stdout.write(`Asset inventory: ${options.exportCsv}\n`);
  }

  return verdict.exitCode;
}
