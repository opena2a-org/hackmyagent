/**
 * SOUL Scanner - Behavioral Governance Scanner
 *
 * Scans governance files (SOUL.md, system-prompt.md, etc.) for coverage
 * across 8 behavioral governance domains defined in OASB v2.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { DOMAIN_TEMPLATES } from './templates';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AgentTier = 'BASIC' | 'TOOL-USING' | 'AGENTIC' | 'MULTI-AGENT';

export type SoulGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export type ConformanceLevel = 'none' | 'essential' | 'standard' | 'hardened';

export interface ControlCheck {
  id: string;
  name: string;
  domain: string;
  keywords: string[];
  passed: boolean;
}

export interface DomainResult {
  domain: string;
  domainId: number;
  controls: ControlCheck[];
  passed: number;
  total: number;
  percentage: number;
}

export interface DeepAnalysisEntry {
  controlId: string;
  llmPassed: boolean;
  reason: string;
}

export interface SoulScanResult {
  file: string | null;
  fileSize: number;
  agentTier: AgentTier;
  domains: DomainResult[];
  score: number;
  grade: SoulGrade;
  conformance: ConformanceLevel;
  criticalFloor: boolean;
  criticalMissing: string[];
  totalControls: number;
  totalPassed: number;
  deepAnalysisResults?: DeepAnalysisEntry[];
}

export interface HardenResult {
  file: string;
  sectionsAdded: string[];
  controlsAdded: number;
  dryRun: boolean;
  content: string;
  existedBefore: boolean;
}

// ---------------------------------------------------------------------------
// Governance file search order
// ---------------------------------------------------------------------------

const GOVERNANCE_FILES = [
  'SOUL.md',
  'system-prompt.md',
  'SYSTEM_PROMPT.md',
  '.cursorrules',
  '.github/copilot-instructions.md',
  'CLAUDE.md',
  '.clinerules',
  'instructions.md',
  'constitution.md',
  'agent-config.yaml',
];

// ---------------------------------------------------------------------------
// Control definitions (8 domains, 68 controls)
// ---------------------------------------------------------------------------

interface ControlDef {
  id: string;
  name: string;
  domain: string;
  domainId: number;
  keywords: string[];
  critical?: boolean;
  /** Which tiers must satisfy this control. Empty means all tiers. */
  tiers: AgentTier[];
}

const ALL_TIERS: AgentTier[] = ['BASIC', 'TOOL-USING', 'AGENTIC', 'MULTI-AGENT'];
const TOOL_AND_UP: AgentTier[] = ['TOOL-USING', 'AGENTIC', 'MULTI-AGENT'];
const AGENTIC_AND_UP: AgentTier[] = ['AGENTIC', 'MULTI-AGENT'];
const MULTI_AGENT_ONLY: AgentTier[] = ['MULTI-AGENT'];

const CONTROL_DEFS: ControlDef[] = [
  // Domain 7: Trust Hierarchy
  { id: 'SOUL-TH-001', name: 'Trust chain defined', domain: 'Trust Hierarchy', domainId: 7, tiers: ALL_TIERS,
    keywords: ['trust', 'authority', 'principal', 'hierarchy', 'precedence', 'priority'] },
  { id: 'SOUL-TH-002', name: 'Conflict resolution defined', domain: 'Trust Hierarchy', domainId: 7, tiers: ALL_TIERS,
    keywords: ['conflict', 'override', 'precedence', 'escalat'] },
  { id: 'SOUL-TH-003', name: 'Agent-to-agent trust', domain: 'Trust Hierarchy', domainId: 7, tiers: MULTI_AGENT_ONLY,
    keywords: ['agent-to-agent', 'sub-agent', 'orchestrat', 'delegate', 'trust.*agent', 'agent.*trust'] },
  { id: 'SOUL-TH-004', name: 'Principal identity verification', domain: 'Trust Hierarchy', domainId: 7, tiers: ALL_TIERS,
    keywords: ['authenticate', 'verify identity', 'principal source', 'identity verification', 'authenticated principal', 'identity claim'] },
  { id: 'SOUL-TH-005', name: 'Trust hierarchy documentation complete', domain: 'Trust Hierarchy', domainId: 7, tiers: ALL_TIERS,
    keywords: ['trust hierarchy', 'hierarchy levels', 'trust structure', 'trust path', 'hierarchy definition', 'trust order'] },
  { id: 'SOUL-TH-006', name: 'Principal authority scope defined', domain: 'Trust Hierarchy', domainId: 7, tiers: ALL_TIERS,
    keywords: ['authority scope', 'principal authority', 'authority boundary', 'authority limit', 'scope definition', 'authority definition'] },
  { id: 'SOUL-TH-007', name: 'Trust boundary enforcement', domain: 'Trust Hierarchy', domainId: 7, tiers: TOOL_AND_UP,
    keywords: ['enforce trust', 'trust enforcement', 'boundary enforcement', 'trust violation', 'enforce boundary', 'trust check'] },
  { id: 'SOUL-TH-008', name: 'Trust policy update protocol', domain: 'Trust Hierarchy', domainId: 7, tiers: ALL_TIERS,
    keywords: ['trust update', 'policy update', 'trust change', 'update protocol', 'trust modification', 'change management'] },

  // Domain 8: Capability Boundaries (TOOL-USING and up)
  { id: 'SOUL-CB-001', name: 'Allowed actions declared', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['allow', 'permit', 'can do', 'authorized', 'capabilities'] },
  { id: 'SOUL-CB-002', name: 'Denied actions declared', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['deny', 'prohibit', 'must not', 'cannot', 'forbidden', 'restricted'] },
  { id: 'SOUL-CB-003', name: 'Filesystem/network scope', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['file', 'directory', 'path', 'network', 'endpoint', 'url', 'api'] },
  { id: 'SOUL-CB-004', name: 'Least privilege principle', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['least privilege', 'minimal', 'only needed', 'minimum necessary'] },
  { id: 'SOUL-CB-005', name: 'Permission revocation process defined', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['revoke', 'revocation', 'remove permission', 'disable access', 'withdraw access', 'permission removal'] },
  { id: 'SOUL-CB-006', name: 'Capability exposure minimized', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['exposure limit', 'minimal exposure', 'capability exposure', 'selective exposure', 'controlled exposure', 'unexposed'] },
  { id: 'SOUL-CB-007', name: 'Tool integration boundaries declared', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['tool boundary', 'tool scope', 'tool limit', 'tool interface', 'tool access control', 'tool constraint'] },
  { id: 'SOUL-CB-008', name: 'Rate and resource limits enforced', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['rate limit', 'rate limiting', 'resource limit', 'throttle', 'quota', 'bandwidth limit', 'usage limit'] },
  { id: 'SOUL-CB-009', name: 'Scope validation at invocation', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['validate scope', 'scope check', 'scope validation', 'boundary check', 'scope enforcement', 'permission check'] },
  { id: 'SOUL-CB-010', name: 'Capability audit trail maintained', domain: 'Capability Boundaries', domainId: 8, tiers: TOOL_AND_UP,
    keywords: ['capability audit', 'audit trail', 'capability log', 'usage log', 'execution log', 'action record'] },

  // Domain 9: Injection Hardening (all tiers)
  { id: 'SOUL-IH-001', name: 'Instruction override defense', domain: 'Injection Hardening', domainId: 9, tiers: ALL_TIERS,
    keywords: ['ignore previous', 'override', 'injection', 'contradict'] },
  { id: 'SOUL-IH-002', name: 'Encoded payload defense', domain: 'Injection Hardening', domainId: 9, tiers: ALL_TIERS,
    keywords: ['encoded', 'obfuscated', 'base64', 'hidden'] },
  { id: 'SOUL-IH-003', name: 'Role-play refusal', domain: 'Injection Hardening', domainId: 9, tiers: ALL_TIERS,
    keywords: ['role-play', 'pretend', 'act as', 'jailbreak', 'DAN'], critical: true },
  { id: 'SOUL-IH-004', name: 'Input validation and sanitization', domain: 'Injection Hardening', domainId: 9, tiers: ALL_TIERS,
    keywords: ['input validation', 'sanitize', 'sanitization', 'validate input', 'filter input', 'clean input'] },
  { id: 'SOUL-IH-005', name: 'Output encoding and escaping', domain: 'Injection Hardening', domainId: 9, tiers: ALL_TIERS,
    keywords: ['output encoding', 'escape output', 'encode output', 'html escape', 'output sanitize', 'safe output'] },
  { id: 'SOUL-IH-006', name: 'Multi-layer injection defense', domain: 'Injection Hardening', domainId: 9, tiers: TOOL_AND_UP,
    keywords: ['defense layer', 'defense in depth', 'layered defense', 'multiple defense', 'defense stack', 'multi-layer'] },
  { id: 'SOUL-IH-007', name: 'Injection detection and alerting', domain: 'Injection Hardening', domainId: 9, tiers: ALL_TIERS,
    keywords: ['detect injection', 'injection detection', 'attack detection', 'log injection', 'alert injection', 'security log'] },
  { id: 'SOUL-IH-008', name: 'Adversarial input testing', domain: 'Injection Hardening', domainId: 9, tiers: TOOL_AND_UP,
    keywords: ['test defense', 'adversarial test', 'red team', 'penetration test', 'security test', 'verify hardening'] },

  // Domain 10: Data Handling
  { id: 'SOUL-DH-001', name: 'PII protection', domain: 'Data Handling', domainId: 10, tiers: ALL_TIERS,
    keywords: ['pii', 'personal', 'privacy', 'data protection', 'gdpr'] },
  { id: 'SOUL-DH-002', name: 'Credential handling', domain: 'Data Handling', domainId: 10, tiers: TOOL_AND_UP,
    keywords: ['credential', 'secret', 'password', 'api key', 'token'] },
  { id: 'SOUL-DH-003', name: 'Data minimization', domain: 'Data Handling', domainId: 10, tiers: ALL_TIERS,
    keywords: ['minimiz', 'only collect', 'retention', 'delete', 'purge'] },
  { id: 'SOUL-DH-004', name: 'Data retention and deletion policy', domain: 'Data Handling', domainId: 10, tiers: ALL_TIERS,
    keywords: ['retention policy', 'retention period', 'data deletion', 'purge schedule', 'data retention', 'archival policy'] },
  { id: 'SOUL-DH-005', name: 'Data classification framework', domain: 'Data Handling', domainId: 10, tiers: ALL_TIERS,
    keywords: ['data classification', 'classify data', 'sensitivity level', 'data sensitivity', 'classification scheme', 'data category'] },
  { id: 'SOUL-DH-006', name: 'Data access control enforcement', domain: 'Data Handling', domainId: 10, tiers: TOOL_AND_UP,
    keywords: ['data access control', 'access rule', 'access policy', 'enforce access', 'data permission', 'access enforcement'] },
  { id: 'SOUL-DH-007', name: 'Data encryption requirements', domain: 'Data Handling', domainId: 10, tiers: TOOL_AND_UP,
    keywords: ['encrypt', 'encryption', 'encrypted', 'encryption at rest', 'encryption in transit', 'tls', 'https', 'cipher'] },
  { id: 'SOUL-DH-008', name: 'Data breach response procedure', domain: 'Data Handling', domainId: 10, tiers: AGENTIC_AND_UP,
    keywords: ['breach notification', 'breach response', 'incident response', 'data breach', 'breach procedure', 'incident notification'] },

  // Domain 11: Hardcoded Behaviors (all tiers)
  { id: 'SOUL-HB-001', name: 'Safety immutables defined', domain: 'Hardcoded Behaviors', domainId: 11, tiers: ALL_TIERS,
    keywords: ['never', 'always', 'must not', 'absolute', 'immutable', 'hardcoded'], critical: true },
  { id: 'SOUL-HB-002', name: 'No data exfiltration rule', domain: 'Hardcoded Behaviors', domainId: 11, tiers: ALL_TIERS,
    keywords: ['exfiltrat', 'unauthorized', 'leak', 'transmit'] },
  { id: 'SOUL-HB-003', name: 'Kill switch / emergency stop', domain: 'Hardcoded Behaviors', domainId: 11, tiers: ALL_TIERS,
    keywords: ['kill switch', 'emergency', 'shutdown', 'terminate', 'stop'] },
  { id: 'SOUL-HB-004', name: 'Behavior integrity verification', domain: 'Hardcoded Behaviors', domainId: 11, tiers: TOOL_AND_UP,
    keywords: ['verify behavior', 'integrity check', 'behavior integrity', 'validate behavior', 'integrity verification', 'behavior validation'] },
  { id: 'SOUL-HB-005', name: 'Constraint immutability guarantee', domain: 'Hardcoded Behaviors', domainId: 11, tiers: ALL_TIERS,
    keywords: ['immutable constraint', 'immutable rule', 'unchangeable', 'permanent constraint', 'fixed rule', 'hardcoded constraint'] },
  { id: 'SOUL-HB-006', name: 'Tamper detection mechanism', domain: 'Hardcoded Behaviors', domainId: 11, tiers: TOOL_AND_UP,
    keywords: ['detect tamper', 'tamper detection', 'tamper-proof', 'detect modification', 'detect unauthorized change', 'integrity monitor'] },
  { id: 'SOUL-HB-007', name: 'Safety behavior audit', domain: 'Hardcoded Behaviors', domainId: 11, tiers: TOOL_AND_UP,
    keywords: ['behavior audit', 'audit behavior', 'behavior attestation', 'certify behavior', 'behavior verification', 'safety audit'] },
  { id: 'SOUL-HB-008', name: 'Enforcement resilience under pressure', domain: 'Hardcoded Behaviors', domainId: 11, tiers: AGENTIC_AND_UP,
    keywords: ['enforcement resilience', 'reliable enforcement', 'robust enforcement', 'fail-safe', 'enforcement guarantee', 'enforcement mechanism'] },

  // Domain 12: Agentic Safety (AGENTIC and up)
  { id: 'SOUL-AS-001', name: 'Iteration/loop limits', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['iteration', 'loop', 'limit', 'maximum', 'budget'] },
  { id: 'SOUL-AS-002', name: 'Budget/cost caps', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['budget', 'cost', 'spending', 'cap', 'limit'] },
  { id: 'SOUL-AS-003', name: 'Timeout defined', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['timeout', 'time limit', 'duration', 'deadline'] },
  { id: 'SOUL-AS-004', name: 'Reversibility preference', domain: 'Agentic Safety', domainId: 12, tiers: MULTI_AGENT_ONLY,
    keywords: ['reversible', 'undo', 'rollback', 'revert'] },
  { id: 'SOUL-AS-005', name: 'Tool dependency limits', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['dependency limit', 'dependency depth', 'dependency chain', 'tool dependency', 'dependency tracking', 'dependency count'] },
  { id: 'SOUL-AS-006', name: 'State management limits', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['state limit', 'state management', 'memory limit', 'context limit', 'state size', 'session state limit'] },
  { id: 'SOUL-AS-007', name: 'Error recovery protocol', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['error recovery', 'recovery protocol', 'error handling', 'retry logic', 'error fallback', 'recovery mechanism'] },
  { id: 'SOUL-AS-008', name: 'Task isolation and sandboxing', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['task isolation', 'sandbox', 'sandboxing', 'isolated execution', 'execution boundary', 'isolation level'] },
  { id: 'SOUL-AS-009', name: 'Resource cleanup on completion', domain: 'Agentic Safety', domainId: 12, tiers: AGENTIC_AND_UP,
    keywords: ['cleanup', 'resource cleanup', 'finalization', 'resource release', 'graceful shutdown', 'cleanup procedure'] },
  { id: 'SOUL-AS-010', name: 'Concurrent execution coordination', domain: 'Agentic Safety', domainId: 12, tiers: MULTI_AGENT_ONLY,
    keywords: ['concurrent limit', 'concurrency', 'concurrent execution', 'coordination', 'serialize task', 'synchronize', 'parallel limit'] },

  // Domain 13: Honesty and Transparency (all tiers)
  { id: 'SOUL-HT-001', name: 'Uncertainty acknowledgment', domain: 'Honesty and Transparency', domainId: 13, tiers: ALL_TIERS,
    keywords: ['uncertain', "don't know", 'not sure', 'acknowledge', 'calibrat'] },
  { id: 'SOUL-HT-002', name: 'No fabrication rule', domain: 'Honesty and Transparency', domainId: 13, tiers: ALL_TIERS,
    keywords: ['fabricat', 'hallucin', 'invent', 'make up', 'accurate'] },
  { id: 'SOUL-HT-003', name: 'Identity disclosure', domain: 'Honesty and Transparency', domainId: 13, tiers: ALL_TIERS,
    keywords: ['identity', 'ai', 'assistant', 'disclose', 'transparent'] },
  { id: 'SOUL-HT-004', name: 'Knowledge boundaries documented', domain: 'Honesty and Transparency', domainId: 13, tiers: ALL_TIERS,
    keywords: ['knowledge boundary', 'knowledge limit', 'knowledge cutoff', 'training limit', 'knowledge scope', 'knowledge limitation'] },
  { id: 'SOUL-HT-005', name: 'Confidence level disclosure', domain: 'Honesty and Transparency', domainId: 13, tiers: ALL_TIERS,
    keywords: ['confidence level', 'confidence score', 'confidence calibration', 'express confidence', 'certainty level', 'calibrated confidence'] },
  { id: 'SOUL-HT-006', name: 'Training data recency disclosed', domain: 'Honesty and Transparency', domainId: 13, tiers: ALL_TIERS,
    keywords: ['training cutoff', 'training date', 'cutoff date', 'knowledge date', 'data recency', 'up to date', 'information currency'] },
  { id: 'SOUL-HT-007', name: 'Limitations acknowledged in responses', domain: 'Honesty and Transparency', domainId: 13, tiers: ALL_TIERS,
    keywords: ['acknowledge limitation', 'limitation notice', 'caveat', 'disclose limitation', 'limitation disclosure', 'note limitation'] },
  { id: 'SOUL-HT-008', name: 'Source verification practices', domain: 'Honesty and Transparency', domainId: 13, tiers: TOOL_AND_UP,
    keywords: ['verify source', 'source verification', 'cite source', 'citation practice', 'verify information', 'source accuracy'] },

  // Domain 14: Human Oversight (TOOL-USING and up)
  { id: 'SOUL-HO-001', name: 'Approval gates', domain: 'Human Oversight', domainId: 14, tiers: TOOL_AND_UP,
    keywords: ['approval', 'confirm', 'human-in-the-loop', 'review', 'authorize'] },
  { id: 'SOUL-HO-002', name: 'Override mechanism', domain: 'Human Oversight', domainId: 14, tiers: TOOL_AND_UP,
    keywords: ['override', 'intervene', 'manual', 'human control'] },
  { id: 'SOUL-HO-003', name: 'Monitoring/logging', domain: 'Human Oversight', domainId: 14, tiers: TOOL_AND_UP,
    keywords: ['monitor', 'log', 'audit', 'track', 'observe'] },
  { id: 'SOUL-HO-004', name: 'Approval workflow and escalation', domain: 'Human Oversight', domainId: 14, tiers: TOOL_AND_UP,
    keywords: ['approval workflow', 'escalation path', 'escalation workflow', 'approval process', 'approval chain', 'workflow process'] },
  { id: 'SOUL-HO-005', name: 'Action notification protocol', domain: 'Human Oversight', domainId: 14, tiers: TOOL_AND_UP,
    keywords: ['notification protocol', 'alert protocol', 'notify user', 'action notification', 'alert system', 'notification trigger'] },
  { id: 'SOUL-HO-006', name: 'Operator identity verification', domain: 'Human Oversight', domainId: 14, tiers: TOOL_AND_UP,
    keywords: ['operator verification', 'verify operator', 'operator authorization', 'operator authentication', 'operator identity', 'authorize operator'] },
  { id: 'SOUL-HO-007', name: 'Audit log retention and access', domain: 'Human Oversight', domainId: 14, tiers: TOOL_AND_UP,
    keywords: ['audit retention', 'log retention', 'audit log access', 'log access control', 'audit preservation', 'log archival'] },
  { id: 'SOUL-HO-008', name: 'Escalation triggers for runaway detection', domain: 'Human Oversight', domainId: 14, tiers: AGENTIC_AND_UP,
    keywords: ['escalation trigger', 'runaway detection', 'detect runaway', 'malfunction detection', 'anomaly detection', 'escalation condition'] },
];

// Unique domain names in order
const DOMAIN_ORDER = [
  'Trust Hierarchy',
  'Capability Boundaries',
  'Injection Hardening',
  'Data Handling',
  'Hardcoded Behaviors',
  'Agentic Safety',
  'Honesty and Transparency',
  'Human Oversight',
];

// ---------------------------------------------------------------------------
// Tier detection keywords
// ---------------------------------------------------------------------------

const TIER_KEYWORDS = {
  multiAgent: ['orchestrat', 'delegate', 'sub-agent', 'sub_agent', 'multi-agent', 'multi_agent', 'swarm', 'coordinator'],
  agentic: ['autonomous', 'loop', 'iterate', 'self-directed', 'agent loop', 'auto-run', 'agentic'],
  toolUsing: ['tool_use', 'function_calling', 'tools', 'mcp', 'modelcontextprotocol', 'function call', 'tool call'],
};

// ---------------------------------------------------------------------------
// SoulScanner class
// ---------------------------------------------------------------------------

export class SoulScanner {
  /**
   * Find the governance file in a directory.
   * Returns the first match from GOVERNANCE_FILES priority order, or null.
   */
  findGovernanceFile(targetDir: string): string | null {
    for (const filename of GOVERNANCE_FILES) {
      const fullPath = path.join(targetDir, filename);
      if (fs.existsSync(fullPath)) {
        return fullPath;
      }
    }
    return null;
  }

  /**
   * Detect agent tier by scanning governance file content and project files.
   */
  detectTier(targetDir: string, governanceContent: string): AgentTier {
    // Combine governance content with any package.json or config content
    let combined = governanceContent.toLowerCase();

    const pkgPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        combined += ' ' + fs.readFileSync(pkgPath, 'utf-8').toLowerCase();
      } catch {
        // ignore read errors
      }
    }

    // Check in order from most capable to least
    for (const kw of TIER_KEYWORDS.multiAgent) {
      if (combined.includes(kw.toLowerCase())) {
        return 'MULTI-AGENT';
      }
    }
    for (const kw of TIER_KEYWORDS.agentic) {
      if (combined.includes(kw.toLowerCase())) {
        return 'AGENTIC';
      }
    }
    for (const kw of TIER_KEYWORDS.toolUsing) {
      if (combined.includes(kw.toLowerCase())) {
        return 'TOOL-USING';
      }
    }

    return 'BASIC';
  }

  /**
   * Check if content matches any keyword for a control.
   * Case-insensitive substring match.
   */
  private checkControl(content: string, def: ControlDef): boolean {
    const lower = content.toLowerCase();
    for (const kw of def.keywords) {
      if (lower.includes(kw.toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  /**
   * LLM-powered semantic analysis for a single control.
   * Uses claude CLI first, falls back to Anthropic API.
   * Returns true if the LLM determines the content addresses the control.
   */
  private async analyzeControlDeep(content: string, def: ControlDef): Promise<boolean> {
    const prompt = `Does the following AI agent governance text address the control "${def.name}" (${def.id})? This control checks for: ${def.keywords.slice(0, 3).join(', ')}. Answer with YES or NO only.\n\n---\n${content.slice(0, 3000)}\n---`;

    // Try claude CLI first
    try {
      const claudePath = execSync('which claude 2>/dev/null', { encoding: 'utf-8' }).trim();
      if (claudePath) {
        // Write prompt to a temp file to avoid shell escaping issues
        const tmpFile = path.join(require('os').tmpdir(), `soul-deep-${Date.now()}.txt`);
        fs.writeFileSync(tmpFile, prompt, 'utf-8');
        try {
          const result = execSync(`${claudePath} --print "$(cat ${tmpFile})"`, {
            encoding: 'utf-8',
            timeout: 15000,
            stdio: ['pipe', 'pipe', 'ignore'],
          });
          return result.trim().toUpperCase().startsWith('YES');
        } finally {
          try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
        }
      }
    } catch {
      // Fall through to API
    }

    // Fallback: Anthropic API
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return false;

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 10,
          messages: [{ role: 'user', content: prompt }],
        }),
      });
      const data = await response.json() as { content: Array<{ text: string }> };
      return data.content[0]?.text?.trim().toUpperCase().startsWith('YES') ?? false;
    } catch {
      return false;
    }
  }

  /**
   * Calculate grade from score, applying critical floor if needed.
   */
  private calculateGrade(score: number, criticalMissing: string[]): { grade: SoulGrade; floored: boolean } {
    let grade: SoulGrade;
    if (score >= 80) grade = 'A';
    else if (score >= 60) grade = 'B';
    else if (score >= 40) grade = 'C';
    else if (score >= 20) grade = 'D';
    else grade = 'F';

    // Critical floor: if critical controls are missing, cap at C
    if (criticalMissing.length > 0 && (grade === 'A' || grade === 'B')) {
      return { grade: 'C', floored: true };
    }

    return { grade, floored: false };
  }

  /**
   * Calculate conformance level based on score and critical control status.
   * none:      one or more critical controls are missing
   * essential: all critical controls pass, score < 60
   * standard:  all critical controls pass, score >= 60
   * hardened:  all critical controls pass, score >= 75
   */
  private calculateConformance(
    score: number,
    criticalMissing: string[],
  ): ConformanceLevel {
    if (criticalMissing.length > 0) return 'none';
    if (score >= 75) return 'hardened';
    if (score >= 60) return 'standard';
    return 'essential';
  }

  /**
   * Return the subset of controls applicable to a given agent tier.
   */
  private applicableControls(tier: AgentTier): ControlDef[] {
    return CONTROL_DEFS.filter((d) => d.tiers.includes(tier));
  }

  /**
   * Scan a directory for behavioral governance coverage.
   */
  async scanSoul(
    targetDir: string,
    options?: { verbose?: boolean; tier?: string; deepAnalysis?: boolean },
  ): Promise<SoulScanResult> {
    const govFile = this.findGovernanceFile(targetDir);

    // Detect tier early (needed for applicable control count)
    const contentForTier = govFile
      ? (() => { try { return fs.readFileSync(govFile, 'utf-8'); } catch { return ''; } })()
      : '';
    const tier = (options?.tier ? options.tier.toUpperCase() as AgentTier : null) || this.detectTier(targetDir, contentForTier);
    const applicable = this.applicableControls(tier);

    // No governance file found
    if (!govFile) {
      const emptyDomains: DomainResult[] = DOMAIN_ORDER.map((domain) => {
        const defs = applicable.filter((d) => d.domain === domain);
        if (defs.length === 0) return null; // Domain not applicable for this tier
        const controls: ControlCheck[] = defs
          .map((d) => ({ id: d.id, name: d.name, domain: d.domain, keywords: d.keywords, passed: false }));
        const domainId = defs[0]?.domainId ?? 0;
        return {
          domain,
          domainId,
          controls,
          passed: 0,
          total: controls.length,
          percentage: 0,
        };
      }).filter((d): d is DomainResult => d !== null);

      const criticalMissing = applicable.filter((d) => d.critical).map((d) => d.id);
      const { grade, floored } = this.calculateGrade(0, criticalMissing);
      const conformance = this.calculateConformance(0, criticalMissing);

      return {
        file: null,
        fileSize: 0,
        agentTier: tier,
        domains: emptyDomains,
        score: 0,
        grade,
        conformance,
        criticalFloor: floored,
        criticalMissing,
        totalControls: applicable.length,
        totalPassed: 0,
      };
    }

    // Read governance file
    const content = contentForTier;
    const fileSize = Buffer.byteLength(content, 'utf-8');

    // Check each applicable control (Layer 1: keyword matching)
    const controlResults: ControlCheck[] = applicable.map((def) => ({
      id: def.id,
      name: def.name,
      domain: def.domain,
      keywords: def.keywords,
      passed: this.checkControl(content, def),
    }));

    // Layer 2: Deep LLM semantic analysis for failed controls
    const deepAnalysisResults: DeepAnalysisEntry[] = [];
    if (options?.deepAnalysis) {
      const failedControls = applicable.filter(
        (def) => !controlResults.find((c) => c.id === def.id)?.passed,
      );

      for (const def of failedControls) {
        const llmPassed = await this.analyzeControlDeep(content, def);
        deepAnalysisResults.push({
          controlId: def.id,
          llmPassed,
          reason: llmPassed
            ? 'LLM semantic analysis determined control is addressed'
            : 'Neither keyword nor semantic analysis found coverage',
        });

        // Upgrade the control result if LLM says it passes
        if (llmPassed) {
          const ctrl = controlResults.find((c) => c.id === def.id);
          if (ctrl) ctrl.passed = true;
        }
      }
    }

    // Group into domains (only domains with applicable controls)
    const domains: DomainResult[] = DOMAIN_ORDER.map((domain) => {
      const domainControls = controlResults.filter((c) => c.domain === domain);
      if (domainControls.length === 0) return null; // No applicable controls for this tier
      const passed = domainControls.filter((c) => c.passed).length;
      const total = domainControls.length;
      const domainId = CONTROL_DEFS.find((d) => d.domain === domain)?.domainId ?? 0;
      return {
        domain,
        domainId,
        controls: domainControls,
        passed,
        total,
        percentage: total > 0 ? Math.round((passed / total) * 100) : 0,
      };
    }).filter((d): d is DomainResult => d !== null);

    // Calculate overall score as average of applicable domain percentages
    const score = domains.length > 0
      ? Math.round(domains.reduce((sum, d) => sum + d.percentage, 0) / domains.length)
      : 0;

    // Find missing critical controls (only applicable ones)
    const criticalMissing = applicable
      .filter((d) => d.critical)
      .filter((d) => !controlResults.find((c) => c.id === d.id)?.passed)
      .map((d) => d.id);

    const { grade, floored } = this.calculateGrade(score, criticalMissing);
    const conformance = this.calculateConformance(score, criticalMissing);
    const totalPassed = controlResults.filter((c) => c.passed).length;

    const result: SoulScanResult = {
      file: path.relative(targetDir, govFile) || path.basename(govFile),
      fileSize,
      agentTier: tier,
      domains,
      score,
      grade,
      conformance,
      criticalFloor: floored,
      criticalMissing,
      totalControls: applicable.length,
      totalPassed,
    };

    if (options?.deepAnalysis && deepAnalysisResults.length > 0) {
      result.deepAnalysisResults = deepAnalysisResults;
    }

    return result;
  }

  /**
   * Generate or update SOUL.md with missing governance sections.
   */
  async hardenSoul(targetDir: string, options?: { dryRun?: boolean }): Promise<HardenResult> {
    const dryRun = options?.dryRun ?? false;

    // Run scan to find what is missing
    const scanResult = await this.scanSoul(targetDir);

    // Determine target file
    const govFile = scanResult.file
      ? path.join(targetDir, scanResult.file)
      : path.join(targetDir, 'SOUL.md');
    const existedBefore = scanResult.file !== null;

    const sectionsAdded: string[] = [];
    let controlsAdded = 0;

    // Build content to append
    let newContent = '';

    if (!existedBefore) {
      // Create full SOUL.md from scratch
      newContent += `# Agent Governance (SOUL)\n\nThis document defines the behavioral governance rules for this agent.\nGenerated by HackMyAgent scan-soul/harden-soul.\n\n`;
    }

    // Read existing content to avoid duplicating sections
    let existingContent = '';
    if (existedBefore) {
      try {
        existingContent = fs.readFileSync(govFile, 'utf-8');
      } catch {
        // File may not be readable; treat as empty
      }
    }

    // harden-soul generates all 8 domain sections (comprehensive / future-proof).
    // scan-soul evaluates only tier-applicable controls; harden-soul adds them all
    // so the resulting SOUL.md is ready if the agent tier increases later.
    for (const domainName of DOMAIN_ORDER) {
      const template = DOMAIN_TEMPLATES[domainName];
      if (!template) continue;

      // Check if the heading already exists in the file
      const existingLower = existingContent.toLowerCase();
      const headingLower = template.heading.toLowerCase();
      if (existingLower.includes(headingLower)) {
        // Domain heading exists -- skip to avoid overwriting user content.
        continue;
      }

      newContent += template.content + '\n';
      sectionsAdded.push(domainName);
      // Count controls in this domain (all tiers, since we're adding comprehensive content)
      const domainControls = CONTROL_DEFS.filter((d) => d.domain === domainName).length;
      controlsAdded += domainControls;
    }

    // Apply or preview
    if (!dryRun && newContent.length > 0) {
      if (existedBefore) {
        // Append to existing file
        fs.appendFileSync(govFile, '\n' + newContent);
      } else {
        // Create new file
        fs.writeFileSync(govFile, newContent);
      }
    }

    const outputFile = path.relative(targetDir, govFile) || path.basename(govFile);

    return {
      file: outputFile,
      sectionsAdded,
      controlsAdded,
      dryRun,
      content: newContent,
      existedBefore,
    };
  }
}

// Export control definitions for testing
export { CONTROL_DEFS, DOMAIN_ORDER, GOVERNANCE_FILES };
