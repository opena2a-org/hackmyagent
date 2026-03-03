/**
 * OASB v2 Behavioral Governance Types
 *
 * Defines the type system for domains 7-14 of the Open Agent Security
 * Benchmark, covering behavioral governance controls derived from the
 * Agent Behavioral Governance Rubric (ABGR).
 */

export type GovernanceSeverity = 'critical' | 'high' | 'medium' | 'low';

export type GovernanceDomain =
  | 'trust-hierarchy'
  | 'capability-boundaries'
  | 'injection-hardening'
  | 'data-handling'
  | 'hardcoded-behaviors'
  | 'agentic-safety'
  | 'honesty-transparency'
  | 'human-oversight';

export type AgentTier = 'basic' | 'tool-using' | 'agentic' | 'multi-agent';

export type GovernanceGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface GovernanceControl {
  id: string;
  domain: GovernanceDomain;
  domainNumber: number;
  name: string;
  description: string;
  severity: GovernanceSeverity;
  keywords: string[][];  // Groups of keywords -- any group match = keyword hit
  requiredForTier: AgentTier[];  // Which tiers this control applies to
}

export interface GovernanceDetectionResult {
  controlId: string;
  detected: boolean;
  confidence: number;    // 0.0 - 1.0
  evidence: string[];    // Lines/sections that matched
  layer: 'structural' | 'keyword' | 'both';
}

export interface GovernanceResult {
  controlId: string;
  controlName: string;
  domain: GovernanceDomain;
  severity: GovernanceSeverity;
  passed: boolean;
  confidence: number;
  evidence: string[];
  remediation?: string;
}

export interface DomainScore {
  domain: GovernanceDomain;
  domainNumber: number;
  domainName: string;
  score: number;         // 0-100
  controlsPassed: number;
  controlsTotal: number;
  controlsFailed: string[];  // IDs of failed controls
}

export interface GovernanceScore {
  overall: number;       // 0-100
  grade: GovernanceGrade;
  domains: DomainScore[];
  results: GovernanceResult[];
  criticalFailures: string[];  // IDs of failed critical controls
  tier: AgentTier;
  tierApplicable: number;      // Controls applicable for this tier
  tierPassed: number;
  sourceFile: string;
}
