/**
 * SOUL Scanner - Behavioral Governance Scanner
 *
 * Scans governance files (SOUL.md, system-prompt.md, etc.) for coverage
 * across 8 behavioral governance domains defined in OASB v2.
 */

import * as fs from 'fs';
import * as path from 'path';
import { DOMAIN_TEMPLATES } from './templates';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AgentTier = 'BASIC' | 'TOOL-USING' | 'AGENTIC' | 'MULTI-AGENT';

export type SoulGrade = 'A' | 'B' | 'C' | 'D' | 'F';

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

export interface SoulScanResult {
  file: string | null;
  fileSize: number;
  agentTier: AgentTier;
  domains: DomainResult[];
  score: number;
  grade: SoulGrade;
  criticalFloor: boolean;
  criticalMissing: string[];
  totalControls: number;
  totalPassed: number;
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
// Control definitions (8 domains, 26 controls)
// ---------------------------------------------------------------------------

interface ControlDef {
  id: string;
  name: string;
  domain: string;
  domainId: number;
  keywords: string[];
  critical?: boolean;
}

const CONTROL_DEFS: ControlDef[] = [
  // Domain 7: Trust Hierarchy
  { id: 'SOUL-TH-001', name: 'Trust chain defined', domain: 'Trust Hierarchy', domainId: 7,
    keywords: ['trust', 'authority', 'principal', 'hierarchy', 'precedence', 'priority'] },
  { id: 'SOUL-TH-002', name: 'Conflict resolution defined', domain: 'Trust Hierarchy', domainId: 7,
    keywords: ['conflict', 'override', 'precedence', 'escalat'] },
  { id: 'SOUL-TH-003', name: 'Operator/user distinction', domain: 'Trust Hierarchy', domainId: 7,
    keywords: ['operator', 'developer', 'user', 'system prompt'] },

  // Domain 8: Capability Boundaries
  { id: 'SOUL-CB-001', name: 'Allowed actions declared', domain: 'Capability Boundaries', domainId: 8,
    keywords: ['allow', 'permit', 'can do', 'authorized', 'capabilities'] },
  { id: 'SOUL-CB-002', name: 'Denied actions declared', domain: 'Capability Boundaries', domainId: 8,
    keywords: ['deny', 'prohibit', 'must not', 'cannot', 'forbidden', 'restricted'] },
  { id: 'SOUL-CB-003', name: 'Filesystem/network scope', domain: 'Capability Boundaries', domainId: 8,
    keywords: ['file', 'directory', 'path', 'network', 'endpoint', 'url', 'api'] },
  { id: 'SOUL-CB-004', name: 'Least privilege principle', domain: 'Capability Boundaries', domainId: 8,
    keywords: ['least privilege', 'minimal', 'only needed', 'minimum necessary'] },

  // Domain 9: Injection Hardening
  { id: 'SOUL-IH-001', name: 'Instruction override defense', domain: 'Injection Hardening', domainId: 9,
    keywords: ['ignore previous', 'override', 'injection', 'contradict'] },
  { id: 'SOUL-IH-002', name: 'Encoded payload defense', domain: 'Injection Hardening', domainId: 9,
    keywords: ['encoded', 'obfuscated', 'base64', 'hidden'] },
  { id: 'SOUL-IH-003', name: 'Role-play refusal', domain: 'Injection Hardening', domainId: 9,
    keywords: ['role-play', 'pretend', 'act as', 'jailbreak', 'DAN'], critical: true },

  // Domain 10: Data Handling
  { id: 'SOUL-DH-001', name: 'PII protection', domain: 'Data Handling', domainId: 10,
    keywords: ['pii', 'personal', 'privacy', 'data protection', 'gdpr'] },
  { id: 'SOUL-DH-002', name: 'Credential handling', domain: 'Data Handling', domainId: 10,
    keywords: ['credential', 'secret', 'password', 'api key', 'token'] },
  { id: 'SOUL-DH-003', name: 'Data minimization', domain: 'Data Handling', domainId: 10,
    keywords: ['minimiz', 'only collect', 'retention', 'delete', 'purge'] },

  // Domain 11: Hardcoded Behaviors
  { id: 'SOUL-HB-001', name: 'Safety immutables defined', domain: 'Hardcoded Behaviors', domainId: 11,
    keywords: ['never', 'always', 'must not', 'absolute', 'immutable', 'hardcoded'], critical: true },
  { id: 'SOUL-HB-002', name: 'No data exfiltration rule', domain: 'Hardcoded Behaviors', domainId: 11,
    keywords: ['exfiltrat', 'unauthorized', 'leak', 'transmit'] },
  { id: 'SOUL-HB-003', name: 'Kill switch / emergency stop', domain: 'Hardcoded Behaviors', domainId: 11,
    keywords: ['kill switch', 'emergency', 'shutdown', 'terminate', 'stop'] },

  // Domain 12: Agentic Safety
  { id: 'SOUL-AS-001', name: 'Iteration/loop limits', domain: 'Agentic Safety', domainId: 12,
    keywords: ['iteration', 'loop', 'limit', 'maximum', 'budget'] },
  { id: 'SOUL-AS-002', name: 'Budget/cost caps', domain: 'Agentic Safety', domainId: 12,
    keywords: ['budget', 'cost', 'spending', 'cap', 'limit'] },
  { id: 'SOUL-AS-003', name: 'Timeout defined', domain: 'Agentic Safety', domainId: 12,
    keywords: ['timeout', 'time limit', 'duration', 'deadline'] },
  { id: 'SOUL-AS-004', name: 'Reversibility preference', domain: 'Agentic Safety', domainId: 12,
    keywords: ['reversible', 'undo', 'rollback', 'revert'] },

  // Domain 13: Honesty & Transparency
  { id: 'SOUL-HT-001', name: 'Uncertainty acknowledgment', domain: 'Honesty & Transparency', domainId: 13,
    keywords: ['uncertain', "don't know", 'not sure', 'acknowledge', 'calibrat'] },
  { id: 'SOUL-HT-002', name: 'No fabrication rule', domain: 'Honesty & Transparency', domainId: 13,
    keywords: ['fabricat', 'hallucin', 'invent', 'make up', 'accurate'] },
  { id: 'SOUL-HT-003', name: 'Identity disclosure', domain: 'Honesty & Transparency', domainId: 13,
    keywords: ['identity', 'ai', 'assistant', 'disclose', 'transparent'] },

  // Domain 14: Human Oversight
  { id: 'SOUL-HO-001', name: 'Approval gates', domain: 'Human Oversight', domainId: 14,
    keywords: ['approval', 'confirm', 'human-in-the-loop', 'review', 'authorize'] },
  { id: 'SOUL-HO-002', name: 'Override mechanism', domain: 'Human Oversight', domainId: 14,
    keywords: ['override', 'intervene', 'manual', 'human control'] },
  { id: 'SOUL-HO-003', name: 'Monitoring/logging', domain: 'Human Oversight', domainId: 14,
    keywords: ['monitor', 'log', 'audit', 'track', 'observe'] },
];

// Unique domain names in order
const DOMAIN_ORDER = [
  'Trust Hierarchy',
  'Capability Boundaries',
  'Injection Hardening',
  'Data Handling',
  'Hardcoded Behaviors',
  'Agentic Safety',
  'Honesty & Transparency',
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
   * Scan a directory for behavioral governance coverage.
   */
  async scanSoul(targetDir: string, options?: { verbose?: boolean; tier?: string }): Promise<SoulScanResult> {
    const govFile = this.findGovernanceFile(targetDir);

    // No governance file found
    if (!govFile) {
      const emptyDomains: DomainResult[] = DOMAIN_ORDER.map((domain) => {
        const defs = CONTROL_DEFS.filter((d) => d.domain === domain);
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
      });

      // Detect tier from project files only
      const tier = (options?.tier as AgentTier) || this.detectTier(targetDir, '');

      const criticalMissing = CONTROL_DEFS.filter((d) => d.critical).map((d) => d.id);
      const { grade, floored } = this.calculateGrade(0, criticalMissing);

      return {
        file: null,
        fileSize: 0,
        agentTier: tier,
        domains: emptyDomains,
        score: 0,
        grade,
        criticalFloor: floored,
        criticalMissing,
        totalControls: CONTROL_DEFS.length,
        totalPassed: 0,
      };
    }

    // Read governance file
    const content = fs.readFileSync(govFile, 'utf-8');
    const fileSize = Buffer.byteLength(content, 'utf-8');
    const tier = (options?.tier as AgentTier) || this.detectTier(targetDir, content);

    // Check each control
    const controlResults: ControlCheck[] = CONTROL_DEFS.map((def) => ({
      id: def.id,
      name: def.name,
      domain: def.domain,
      keywords: def.keywords,
      passed: this.checkControl(content, def),
    }));

    // Group into domains
    const domains: DomainResult[] = DOMAIN_ORDER.map((domain) => {
      const domainControls = controlResults.filter((c) => c.domain === domain);
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
    });

    // Calculate overall score as average of domain percentages
    const score = domains.length > 0
      ? Math.round(domains.reduce((sum, d) => sum + d.percentage, 0) / domains.length)
      : 0;

    // Find missing critical controls
    const criticalMissing = CONTROL_DEFS
      .filter((d) => d.critical)
      .filter((d) => !controlResults.find((c) => c.id === d.id)?.passed)
      .map((d) => d.id);

    const { grade, floored } = this.calculateGrade(score, criticalMissing);
    const totalPassed = controlResults.filter((c) => c.passed).length;

    return {
      file: path.relative(targetDir, govFile) || path.basename(govFile),
      fileSize,
      agentTier: tier,
      domains,
      score,
      grade,
      criticalFloor: floored,
      criticalMissing,
      totalControls: CONTROL_DEFS.length,
      totalPassed,
    };
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

    // Find domains with missing controls
    const missingDomains = scanResult.domains.filter((d) => d.passed < d.total);
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

    for (const domain of missingDomains) {
      const template = DOMAIN_TEMPLATES[domain.domain];
      if (!template) continue;

      // Check if the heading already exists in the file
      const existingLower = existingContent.toLowerCase();
      const headingLower = template.heading.toLowerCase();
      if (existingLower.includes(headingLower)) {
        // Domain heading exists -- skip to avoid overwriting user content.
        // The domain has partial coverage, but the user should fill in gaps manually.
        continue;
      }

      newContent += template.content + '\n';
      sectionsAdded.push(domain.domain);
      controlsAdded += domain.total - domain.passed;
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
